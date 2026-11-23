// Package keystore manages the device identity (X25519 age identity + Ed25519
// signing key) and small non-secret client state.
//
// Secrets live in the OS keychain (service "ecb") with an automatic fallback
// to a 0600 file in the config dir (os.UserConfigDir()/ecb, mode 0700) when the
// keychain is unavailable, e.g. on headless Linux. Non-secret state is a JSON
// file written atomically. Key material is never logged or included in errors.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// Get returns the secret or ErrNotFound.
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

// Options configure a Store.
type Options struct {
	// Dir is the config dir; empty means os.UserConfigDir()/ecb.
	Dir string
	// ForceFile disables the keychain and always uses the 0600 file.
	ForceFile bool
	// Keyring overrides the keychain backend (tests); nil means the OS keychain.
	Keyring SecretBackend
}

// Store persists the identity and client state.
type Store struct {
	dir string
	kr  SecretBackend // nil when ForceFile
	mu  sync.Mutex
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
	s := &Store{dir: dir}
	if !o.ForceFile {
		s.kr = o.Keyring
		if s.kr == nil {
			s.kr = osKeyring{}
		}
	}
	return s, nil
}

// Dir returns the config directory.
func (s *Store) Dir() string { return s.dir }

// SaveIdentity stores id in the keychain, or in the 0600 file when the
// keychain is unavailable (or forced off).
func (s *Store) SaveIdentity(id *Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret := id.encode()
	if s.kr != nil {
		if err := s.kr.Set(secret); err == nil {
			_ = os.Remove(filepath.Join(s.dir, identityFile))
			return nil
		}
	}
	return writeFileAtomic(filepath.Join(s.dir, identityFile), []byte(secret))
}

// LoadIdentity returns the stored identity, or ErrNotFound.
func (s *Store) LoadIdentity() (*Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kr != nil {
		if sec, err := s.kr.Get(); err == nil {
			return decodeIdentity(sec)
		}
		// not found or keychain unavailable: try the file
	}
	b, err := os.ReadFile(filepath.Join(s.dir, identityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeIdentity(string(b))
}

// LoadOrCreateIdentity loads the identity, generating and saving one if absent.
func (s *Store) LoadOrCreateIdentity() (*Identity, bool, error) {
	id, err := s.LoadIdentity()
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}
	if id, err = Generate(); err != nil {
		return nil, false, err
	}
	if err := s.SaveIdentity(id); err != nil {
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
	if err := os.Remove(filepath.Join(s.dir, identityFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
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

// LoadState reads the state file; a missing file yields an empty State.
func (s *Store) LoadState() (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	st := &State{RelayURL: j.RelayURL, LastCounters: j.LastCounters, SendCounter: j.SendCounter}
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

// SaveState atomically writes the state file with mode 0600.
func (s *Store) SaveState(st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := stateJSON{RelayURL: st.RelayURL, LastCounters: st.LastCounters, SendCounter: st.SendCounter}
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
