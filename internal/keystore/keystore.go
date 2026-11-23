// Package keystore manages the device identity (X25519 age identity + Ed25519
// signing key) and small non-secret client state.
//
// Secrets live in the OS keychain (service "ecb") with an automatic fallback
// to a 0600 file in the config dir (os.UserConfigDir()/ecb, mode 0700) when the
// keychain is unavailable, e.g. on headless Linux. Non-secret state is a JSON
// file written atomically. Key material is never logged or included in errors.
package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
)

const (
	// Service is the keychain service name.
	Service = "ecb"
	keyUser = "device-key"

	identityFile = "identity.key"
	stateFile    = "state.json"
	lockName     = "state.lock"
	secretMagic  = "ecb-key-v1"
)

// ErrNotFound means no identity has been stored yet.
var ErrNotFound = errors.New("keystore: identity not found")

// Identity is a device identity.
type Identity struct {
	// X25519 is the age identity used to decrypt items.
	X25519 *age.X25519Identity
	// Ed25519 is the signing key.
	Ed25519 ed25519.PrivateKey
}

// Generate creates a fresh identity.
func Generate() (*Identity, error) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{X25519: x, Ed25519: sk}, nil
}

// PublicKey returns the Ed25519 public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.Ed25519.Public().(ed25519.PublicKey) }

// DeviceID returns SHA-256(ed25519 public key)[:16].
func (i *Identity) DeviceID() [16]byte {
	s := sha256.Sum256(i.PublicKey())
	var id [16]byte
	copy(id[:], s[:16])
	return id
}

// Recipient returns the age recipient string ("age1...").
func (i *Identity) Recipient() string { return i.X25519.Recipient().String() }

// encode serialises the identity: magic, age secret key, base64 ed25519 seed.
func (i *Identity) encode() string {
	return secretMagic + "\n" + i.X25519.String() + "\n" + base64.StdEncoding.EncodeToString(i.Ed25519.Seed()) + "\n"
}

func decodeIdentity(s string) (*Identity, error) {
	parts := strings.Split(strings.TrimSpace(s), "\n")
	if len(parts) != 3 || parts[0] != secretMagic {
		return nil, errors.New("keystore: corrupt identity")
	}
	x, err := age.ParseX25519Identity(parts[1])
	if err != nil {
		return nil, errors.New("keystore: corrupt identity")
	}
	seed, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("keystore: corrupt identity")
	}
	return &Identity{X25519: x, Ed25519: ed25519.NewKeyFromSeed(seed)}, nil
}

// SecretBackend is a place to keep the identity secret (the OS keychain).
type SecretBackend interface {
	// Get returns the secret or ErrNotFound (and only ErrNotFound when the
	// keychain works but holds no entry; any other error means "unavailable").
	Get() (string, error)
	Set(secret string) error
	Delete() error
}

type osKeyring struct{}

func (osKeyring) Get() (string, error) {
	s, err := keyring.Get(Service, keyUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return s, err
}
func (osKeyring) Set(s string) error { return keyring.Set(Service, keyUser, s) }
func (osKeyring) Delete() error {
	err := keyring.Delete(Service, keyUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// Backend selects where the identity secret lives.
type Backend string

const (
	// BackendAuto prefers the keychain; the identity file is only read when the
	// keychain has no entry or is unavailable, and only written when
	// AllowFileFallback is set.
	BackendAuto Backend = "auto"
	// BackendKeychain uses the keychain only (the file is touched only when
	// AllowFileFallback is set).
	BackendKeychain Backend = "keychain"
	// BackendFile uses the 0600 identity file only.
	BackendFile Backend = "file"
)

// EnvBackend is the environment variable (file|keychain|auto) that overrides
// Options.Backend.
const EnvBackend = "ECB_KEYSTORE"

// ErrKeychainUnavailable means the OS keychain failed (locked, denied, no
// secret service) and no allowed fallback could serve the request. The
// identity was NOT created or replaced. It wraps the keychain error.
var ErrKeychainUnavailable = errors.New("keystore: OS keychain unavailable")

// ErrInsecureFile means the identity file is accessible by group/other.
var ErrInsecureFile = errors.New("keystore: identity file permissions too open")

// Options configure a Store.
type Options struct {
	// Dir is the config dir; empty means os.UserConfigDir()/ecb.
	Dir string
	// Backend selects the secret backend; empty means auto. The ECB_KEYSTORE
	// environment variable (file|keychain|auto) overrides it.
	Backend Backend
	// AllowFileFallback permits writing the identity to the 0600 file when the
	// keychain fails. Default false; implied by Backend == BackendFile.
	AllowFileFallback bool
	// ForceFile is legacy shorthand for Backend == BackendFile that never
	// touches the OS keychain (not even to delete a stale entry), unless
	// Keyring is injected.
	ForceFile bool
	// Keyring overrides the keychain backend (tests); nil means the OS keychain.
	Keyring SecretBackend
}

// Store persists the identity and client state.
type Store struct {
	dir      string
	kr       SecretBackend // nil when no keychain should be touched
	backend  Backend
	fallback bool
	mu       sync.Mutex
	active   string
}

// Open creates a Store, creating the config dir with mode 0700.
func Open(o Options) (*Store, error) {
	dir := o.Dir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		dir = filepath.Join(base, "ecb")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	b := o.Backend
	if o.ForceFile {
		b = BackendFile
	}
	if env := strings.ToLower(strings.TrimSpace(os.Getenv(EnvBackend))); env != "" {
		b = Backend(env)
	}
	switch b {
	case "":
		b = BackendAuto
	case BackendAuto, BackendKeychain, BackendFile:
	default:
		return nil, fmt.Errorf("keystore: invalid backend %q (want auto, keychain or file)", b)
	}
	s := &Store{dir: dir, backend: b, fallback: o.AllowFileFallback || b == BackendFile}
	s.kr = o.Keyring
	// The file backend never touches the real OS keychain (not even to delete
	// a stale entry); only an injected Keyring is used then.
	if s.kr == nil && b != BackendFile {
		s.kr = osKeyring{}
	}
	if b == BackendFile {
		s.active = "file"
	} else {
		s.active = "keychain"
	}
	return s, nil
}

// Dir returns the config directory.
func (s *Store) Dir() string { return s.dir }

// Backend returns the backend currently holding the identity: "keychain" or
// "file". It reflects the last load/save, so the CLI should call it after
// LoadOrCreateIdentity and warn loudly when it is "file" although the keychain
// was requested (file fallback in use).
func (s *Store) Backend() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *Store) idPath() string { return filepath.Join(s.dir, identityFile) }

// readIdentityFile reads the identity file, refusing group/other-accessible
// modes (unix). Returns ErrNotFound when absent.
func (s *Store) readIdentityFile() (*Identity, error) {
	f, err := os.Open(s.idPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if runtime.GOOS != "windows" {
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s has mode %04o; run: chmod 600 %s", ErrInsecureFile, s.idPath(), fi.Mode().Perm(), s.idPath())
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	return decodeIdentity(string(b))
}

func (s *Store) writeIdentityFile(secret string) error {
	if err := writeFileAtomic(s.idPath(), []byte(secret)); err != nil {
		return err
	}
	s.active = "file"
	return nil
}

func (s *Store) deleteStaleKeychain() {
	if s.kr != nil {
		_ = s.kr.Delete()
	}
}

// SaveIdentity stores id in the keychain. If the keychain fails it returns
// ErrKeychainUnavailable unless file fallback is allowed, in which case the
// 0600 file is written (see Backend). The identity in the other backend is
// removed best-effort so a stale copy can never shadow the new one.
func (s *Store) SaveIdentity(id *Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveIdentity(id)
}

func (s *Store) saveIdentity(id *Identity) error {
	secret := id.encode()
	if s.backend != BackendFile && s.kr != nil {
		err := s.kr.Set(secret)
		if err == nil {
			_ = os.Remove(s.idPath())
			s.active = "keychain"
			return nil
		}
		if !s.fallback {
			return fmt.Errorf("%w: %w", ErrKeychainUnavailable, err)
		}
	} else if s.backend != BackendFile {
		return fmt.Errorf("%w: no keychain backend", ErrKeychainUnavailable)
	}
	if err := s.writeIdentityFile(secret); err != nil {
		return err
	}
	s.deleteStaleKeychain()
	return nil
}

// LoadIdentity returns the stored identity or ErrNotFound. A keychain failure
// (anything but "no entry") falls back to an existing identity file, else
// returns ErrKeychainUnavailable; it never reports ErrNotFound in that case.
func (s *Store) LoadIdentity() (*Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadIdentity()
}

func (s *Store) loadIdentity() (*Identity, error) {
	if s.backend == BackendFile || s.kr == nil {
		if s.backend != BackendFile {
			return nil, fmt.Errorf("%w: no keychain backend", ErrKeychainUnavailable)
		}
		id, err := s.readIdentityFile()
		if err == nil {
			s.active = "file"
		}
		return id, err
	}
	sec, err := s.kr.Get()
	if err == nil {
		id, derr := decodeIdentity(sec)
		if derr == nil {
			s.active = "keychain"
		}
		return id, derr
	}
	readFile := s.backend == BackendAuto || s.fallback
	if errors.Is(err, ErrNotFound) || errors.Is(err, keyring.ErrNotFound) {
		if !readFile {
			return nil, ErrNotFound
		}
		return s.fromFile(ErrNotFound)
	}
	// Keychain locked/denied/unavailable: never claim "not found".
	if !readFile {
		return nil, fmt.Errorf("%w: %w", ErrKeychainUnavailable, err)
	}
	return s.fromFile(fmt.Errorf("%w: %w", ErrKeychainUnavailable, err))
}

// fromFile reads the identity file; when it is absent it returns missing.
func (s *Store) fromFile(missing error) (*Identity, error) {
	id, err := s.readIdentityFile()
	if errors.Is(err, ErrNotFound) {
		return nil, missing
	}
	if err == nil {
		s.active = "file"
	}
	return id, err
}

// LoadOrCreateIdentity loads the identity, generating and saving one only when
// it is definitively absent (ErrNotFound). It never generates on keychain
// errors, so a working identity cannot be replaced.
func (s *Store) LoadOrCreateIdentity() (*Identity, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(filepath.Join(s.dir, lockName))
	if err != nil {
		return nil, false, err
	}
	defer unlock()
	id, err := s.loadIdentity()
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	if id, err = Generate(); err != nil {
		return nil, false, err
	}
	if err := s.saveIdentity(id); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// DeleteIdentity removes the identity from every backend.
func (s *Store) DeleteIdentity() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr != nil {
		_ = s.kr.Delete()
	}
	if err := os.Remove(s.idPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// State is the small non-secret client state.
type State struct {
	// RelayURL is the relay base URL.
	RelayURL string
	// GroupID is the sync group id.
	GroupID [16]byte
	// RosterBlob is the sealed (opaque) roster.
	RosterBlob []byte
	// RosterVersion is the version of RosterBlob (0 = unknown, e.g. a state
	// file written by an older build). UpdateState never replaces a stored
	// roster with one whose version is not higher (see UpdateState).
	RosterVersion uint64
	// LastCounters maps sender device id (hex) to the highest accepted counter.
	LastCounters map[string]uint64
	// SendCounter is this device's last used send counter.
	SendCounter uint64
}

// stateJSON is the on-disk shape (hex/base64 for binary fields).
type stateJSON struct {
	RelayURL     string            `json:"relay_url,omitempty"`
	GroupID      string            `json:"group_id,omitempty"`
	RosterBlob   string            `json:"roster_blob,omitempty"`
	RosterVer    uint64            `json:"roster_version,omitempty"`
	LastCounters map[string]uint64 `json:"last_counters,omitempty"`
	SendCounter  uint64            `json:"send_counter,omitempty"`
}

// LastCounter returns the highest accepted counter from sender.
func (st *State) LastCounter(sender [16]byte) uint64 {
	return st.LastCounters[fmt.Sprintf("%x", sender)]
}

// SetLastCounter records an accepted counter (only increases it).
func (st *State) SetLastCounter(sender [16]byte, c uint64) {
	if st.LastCounters == nil {
		st.LastCounters = map[string]uint64{}
	}
	k := fmt.Sprintf("%x", sender)
	if c > st.LastCounters[k] {
		st.LastCounters[k] = c
	}
}

// NextSendCounter increments and returns the send counter.
func (st *State) NextSendCounter() uint64 { st.SendCounter++; return st.SendCounter }

func (s *Store) readState() (*State, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var j stateJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("keystore: corrupt state: %w", err)
	}
	st := &State{RelayURL: j.RelayURL, LastCounters: j.LastCounters, SendCounter: j.SendCounter, RosterVersion: j.RosterVer}
	if j.GroupID != "" {
		g, err := hex.DecodeString(j.GroupID)
		if err != nil || len(g) != 16 {
			return nil, errors.New("keystore: corrupt state: group_id")
		}
		copy(st.GroupID[:], g)
	}
	if j.RosterBlob != "" {
		if st.RosterBlob, err = base64.StdEncoding.DecodeString(j.RosterBlob); err != nil {
			return nil, errors.New("keystore: corrupt state: roster_blob")
		}
	}
	return st, nil
}

// LoadState reads the state file; a missing file yields an empty State. Writes
// are atomic renames, so no lock is needed for a consistent snapshot; use
// UpdateState for read-modify-write.
func (s *Store) LoadState() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readState()
}

// UpdateState runs fn on the current state under an exclusive cross-process
// file lock (state.lock in the config dir) and writes the result atomically
// (0600). The state is re-read under the lock; LastCounters and SendCounter
// are merged by MAX with what is on disk, so they never decrease. The stored
// roster only moves forward: if fn changes RosterBlob of the same group, it
// must also set RosterVersion higher than the stored one, otherwise the stored
// roster is kept (a stale in-memory copy can never roll the roster back). If fn
// returns an error nothing is written and the error is returned.
func (s *Store) UpdateState(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(filepath.Join(s.dir, lockName))
	if err != nil {
		return err
	}
	defer unlock()
	st, err := s.readState()
	if err != nil {
		return err
	}
	disk := make(map[string]uint64, len(st.LastCounters))
	for k, v := range st.LastCounters {
		disk[k] = v
	}
	diskSend := st.SendCounter
	diskBlob := append([]byte(nil), st.RosterBlob...)
	diskVer, diskGroup := st.RosterVersion, st.GroupID
	if err := fn(st); err != nil {
		return err
	}
	if !bytes.Equal(st.RosterBlob, diskBlob) && diskVer > 0 && st.GroupID == diskGroup && st.RosterVersion <= diskVer {
		st.RosterBlob, st.RosterVersion = diskBlob, diskVer
	}
	for k, v := range disk {
		if st.LastCounters == nil {
			st.LastCounters = map[string]uint64{}
		}
		if st.LastCounters[k] < v {
			st.LastCounters[k] = v
		}
	}
	if st.SendCounter < diskSend {
		st.SendCounter = diskSend
	}
	j := stateJSON{RelayURL: st.RelayURL, LastCounters: st.LastCounters, SendCounter: st.SendCounter, RosterVer: st.RosterVersion}
	if st.GroupID != ([16]byte{}) {
		j.GroupID = fmt.Sprintf("%x", st.GroupID)
	}
	if len(st.RosterBlob) > 0 {
		j.RosterBlob = base64.StdEncoding.EncodeToString(st.RosterBlob)
	}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.dir, stateFile), b)
}

// SaveState overwrites the scalar fields (relay, group, roster) with st and
// merges counters by MAX with the on-disk state, under the cross-process lock.
// The roster is subject to the forward-only rule of UpdateState. Long-running
// code that only needs to persist counters must use UpdateState,
// NextSendCounter or SetLastCounter instead.
func (s *Store) SaveState(st *State) error {
	return s.UpdateState(func(cur *State) error {
		cur.RelayURL, cur.GroupID, cur.RosterBlob, cur.RosterVersion = st.RelayURL, st.GroupID, st.RosterBlob, st.RosterVersion
		for k, v := range st.LastCounters {
			if cur.LastCounters == nil {
				cur.LastCounters = map[string]uint64{}
			}
			if cur.LastCounters[k] < v {
				cur.LastCounters[k] = v
			}
		}
		if cur.SendCounter < st.SendCounter {
			cur.SendCounter = st.SendCounter
		}
		return nil
	})
}

// SetLastCounter durably records an accepted counter from sender (max-merged).
func (s *Store) SetLastCounter(sender [16]byte, c uint64) error {
	return s.UpdateState(func(st *State) error { st.SetLastCounter(sender, c); return nil })
}

// NextSendCounter atomically increments the persisted send counter, durably
// writes it, and only then returns it. Unique and increasing across processes.
func (s *Store) NextSendCounter() (uint64, error) {
	var n uint64
	err := s.UpdateState(func(st *State) error { n = st.NextSendCounter(); return nil })
	if err != nil {
		return 0, err
	}
	return n, nil
}

// writeFileAtomic writes data to path via a 0600 temp file in the same dir,
// fsyncs, then renames over path.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { f.Close(); os.Remove(tmp) }
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
