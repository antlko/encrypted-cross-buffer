package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	errGroupExists  = errors.New("group exists")
	errNoGroup      = errors.New("no such group")
	errNotMember    = errors.New("signer not a member")
	errOldVersion   = errors.New("version not newer")
	errBadKeySet    = errors.New("invalid key set")
	maxGroupDevices = 64
)

type pubKey [ed25519.PublicKeySize]byte

func (p pubKey) deviceID() [16]byte {
	h := sha256.Sum256(p[:])
	var d [16]byte
	copy(d[:], h[:16])
	return d
}

type group struct {
	keys    map[pubKey]struct{}
	blob    []byte
	version uint64
}

type diskGroup struct {
	GroupID       string   `json:"group_id"`
	Keys          []string `json:"keys"`
	RosterBlob    []byte   `json:"roster_blob"`
	RosterVersion uint64   `json:"roster_version"`
}

type diskState struct {
	Groups []diskGroup `json:"groups"`
}

// groupStore is the persistent group registry (groups.json).
type groupStore struct {
	mu     sync.RWMutex
	path   string
	groups map[string]*group // key: group id hex
}

func openGroupStore(dataDir string) (*groupStore, error) {
	gs := &groupStore{path: filepath.Join(dataDir, "groups.json"), groups: map[string]*group{}}
	b, err := os.ReadFile(gs.path)
	if errors.Is(err, os.ErrNotExist) {
		return gs, nil
	}
	if err != nil {
		return nil, err
	}
	var ds diskState
	if err := json.Unmarshal(b, &ds); err != nil {
		return nil, fmt.Errorf("groups.json: %w", err)
	}
	for _, d := range ds.Groups {
		g := &group{keys: map[pubKey]struct{}{}, blob: d.RosterBlob, version: d.RosterVersion}
		for _, k := range d.Keys {
			raw, err := base64.StdEncoding.DecodeString(k)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return nil, errors.New("groups.json: bad key")
			}
			g.keys[pubKey(raw)] = struct{}{}
		}
		gs.groups[d.GroupID] = g
	}
	return gs, nil
}

// persistLocked writes the whole state atomically (0600). Caller holds mu.
func (gs *groupStore) persistLocked() error {
	var ds diskState
	for id, g := range gs.groups {
		d := diskGroup{GroupID: id, RosterBlob: g.blob, RosterVersion: g.version}
		for k := range g.keys {
			d.Keys = append(d.Keys, base64.StdEncoding.EncodeToString(k[:]))
		}
		ds.Groups = append(ds.Groups, d)
	}
	b, err := json.Marshal(ds)
	if err != nil {
		return err
	}
	return writeFileAtomic(gs.path, b)
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func (gs *groupStore) create(gid string, pub pubKey, blob []byte, version uint64) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	if _, ok := gs.groups[gid]; ok {
		return errGroupExists
	}
	gs.groups[gid] = &group{keys: map[pubKey]struct{}{pub: {}}, blob: blob, version: version}
	if err := gs.persistLocked(); err != nil {
		delete(gs.groups, gid)
		return err
	}
	return nil
}

// publish replaces the roster blob and key set (signer must be in the current set).
func (gs *groupStore) publish(gid string, signer pubKey, version uint64, blob []byte, keys []pubKey) error {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	g := gs.groups[gid]
	if g == nil {
		return errNoGroup
	}
	if _, ok := g.keys[signer]; !ok {
		return errNotMember
	}
	if version <= g.version {
		return errOldVersion
	}
	if len(keys) == 0 || len(keys) > maxGroupDevices {
		return errBadKeySet
	}
	old := *g
	g.keys = make(map[pubKey]struct{}, len(keys))
	for _, k := range keys {
		g.keys[k] = struct{}{}
	}
	g.blob, g.version = blob, version
	if err := gs.persistLocked(); err != nil {
		*g = old
		return err
	}
	return nil
}

func (gs *groupStore) has(gid string, pub pubKey) bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	g := gs.groups[gid]
	if g == nil {
		return false
	}
	_, ok := g.keys[pub]
	return ok
}

func (gs *groupStore) exists(gid string) bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return gs.groups[gid] != nil
}

// keyByDevice snapshots the group's keys indexed by device id.
func (gs *groupStore) keyByDevice(gid string) map[[16]byte]ed25519.PublicKey {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	g := gs.groups[gid]
	if g == nil {
		return nil
	}
	m := make(map[[16]byte]ed25519.PublicKey, len(g.keys))
	for k := range g.keys {
		kk := k
		m[kk.deviceID()] = ed25519.PublicKey(kk[:])
	}
	return m
}

func (gs *groupStore) roster(gid string) ([]byte, uint64, bool) {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	g := gs.groups[gid]
	if g == nil {
		return nil, 0, false
	}
	return g.blob, g.version, true
}

// whileMember runs fn only if pub is (still) a member, holding the read lock so
// a concurrent roster publish cannot complete in between.
func (gs *groupStore) whileMember(gid string, pub pubKey, fn func() error) error {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	g := gs.groups[gid]
	if g == nil {
		return errNotMember
	}
	if _, ok := g.keys[pub]; !ok {
		return errNotMember
	}
	return fn()
}
