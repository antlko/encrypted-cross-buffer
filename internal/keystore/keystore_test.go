package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/antlko/encrypted-cross-buffer/internal/roster"
)

type fakeKR struct {
	secret string
	have   bool
	fail   bool
}

func (f *fakeKR) Get() (string, error) {
	if f.fail {
		return "", errors.New("keyring unavailable")
	}
	if !f.have {
		return "", ErrNotFound
	}
	return f.secret, nil
}
func (f *fakeKR) Set(s string) error {
	if f.fail {
		return errors.New("keyring unavailable")
	}
	f.secret, f.have = s, true
	return nil
}
func (f *fakeKR) Delete() error { f.secret, f.have = "", false; return nil }

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestFileBackendRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ecb")
	s, err := Open(Options{Dir: dir, ForceFile: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadIdentity(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	id, created, err := s.LoadOrCreateIdentity()
	if err != nil || !created {
		t.Fatal(err, created)
	}
	if runtime.GOOS != "windows" {
		if p := perm(t, filepath.Join(dir, "identity.key")); p != 0o600 {
			t.Errorf("identity perm %o", p)
		}
		if p := perm(t, dir); p != 0o700 {
			t.Errorf("dir perm %o", p)
		}
	}
	got, created, err := s.LoadOrCreateIdentity()
	if err != nil || created {
		t.Fatal(err, created)
	}
	if got.X25519.String() != id.X25519.String() || !got.Ed25519.Equal(id.Ed25519) || got.DeviceID() != id.DeviceID() {
		t.Fatal("identity changed on reload")
	}
	// The recipient must match, and signing keys must work.
	if got.Recipient() != id.Recipient() || len(got.Recipient()) < 10 {
		t.Fatal("recipient mismatch")
	}
	if err := s.DeleteIdentity(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadIdentity(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestKeyringPreferredAndFallback(t *testing.T) {
	dir := t.TempDir()
	kr := &fakeKR{}
	s, _ := Open(Options{Dir: dir, Keyring: kr})
	id, _ := Generate()
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if !kr.have {
		t.Fatal("keyring not used")
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.key")); err == nil {
		t.Fatal("secret written to file despite keyring")
	}
	got, err := s.LoadIdentity()
	if err != nil || got.DeviceID() != id.DeviceID() {
		t.Fatal(err)
	}

	// Unavailable keyring, fallback allowed -> file.
	dir2 := t.TempDir()
	s2, _ := Open(Options{Dir: dir2, Keyring: &fakeKR{fail: true}, AllowFileFallback: true})
	if err := s2.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if s2.Backend() != "file" {
		t.Errorf("backend %q", s2.Backend())
	}
	if p := perm(t, filepath.Join(dir2, "identity.key")); p != 0o600 {
		t.Errorf("perm %o", p)
	}
	got, err = s2.LoadIdentity()
	if err != nil || got.DeviceID() != id.DeviceID() {
		t.Fatal(err)
	}
}

func TestKeychainFailureNeverReplacesIdentity(t *testing.T) {
	t.Setenv(EnvBackend, "")
	// Failing keychain, no file: typed error, nothing generated or written.
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir, Keyring: &fakeKR{fail: true}})
	if _, err := s.LoadIdentity(); !errors.Is(err, ErrKeychainUnavailable) || errors.Is(err, ErrNotFound) {
		t.Fatalf("load: %v", err)
	}
	if _, _, err := s.LoadOrCreateIdentity(); !errors.Is(err, ErrKeychainUnavailable) {
		t.Fatalf("create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.key")); err == nil {
		t.Fatal("identity file generated on keychain failure")
	}
	id, _ := Generate()
	if err := s.SaveIdentity(id); !errors.Is(err, ErrKeychainUnavailable) {
		t.Fatalf("save: %v", err)
	}

	// Failing keychain, existing file: file is used, never overwritten.
	fs, _ := Open(Options{Dir: dir, ForceFile: true})
	if err := fs.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	got, created, err := s.LoadOrCreateIdentity()
	if err != nil || created || got.DeviceID() != id.DeviceID() {
		t.Fatalf("%v %v", err, created)
	}
	if s.Backend() != "file" {
		t.Errorf("backend %q", s.Backend())
	}

	// Working keychain without entry and without file -> only then generate.
	kr := &fakeKR{}
	s3, _ := Open(Options{Dir: t.TempDir(), Keyring: kr})
	if _, created, err := s3.LoadOrCreateIdentity(); err != nil || !created || !kr.have || s3.Backend() != "keychain" {
		t.Fatal(err, created)
	}
}

func TestStaleCopiesRemoved(t *testing.T) {
	t.Setenv(EnvBackend, "")
	dir := t.TempDir()
	id, _ := Generate()
	kr := &fakeKR{secret: "old", have: true}
	s, _ := Open(Options{Dir: dir, Backend: BackendFile, Keyring: kr})
	if err := s.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if kr.have {
		t.Fatal("stale keychain entry kept")
	}
	s2, _ := Open(Options{Dir: dir, Keyring: kr})
	if err := s2.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.key")); err == nil {
		t.Fatal("stale file kept")
	}
}

func TestEnvOverrideAndInvalidBackend(t *testing.T) {
	t.Setenv(EnvBackend, "file")
	s, err := Open(Options{Dir: t.TempDir(), Keyring: &fakeKR{fail: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadOrCreateIdentity(); err != nil || s.Backend() != "file" {
		t.Fatal(err)
	}
	t.Setenv(EnvBackend, "bogus")
	if _, err := Open(Options{Dir: t.TempDir()}); err == nil {
		t.Fatal("accepted bogus backend")
	}
}

func TestInsecureIdentityFileRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	if _, _, err := s.LoadOrCreateIdentity(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "identity.key")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoadIdentity()
	if !errors.Is(err, ErrInsecureFile) || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := s.LoadOrCreateIdentity(); err == nil {
		t.Fatal("must not regenerate")
	}
	os.Chmod(p, 0o600)
	if _, err := s.LoadIdentity(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateStateTwoStoresNoLostUpdates(t *testing.T) {
	dir := t.TempDir()
	const stores, per = 4, 40
	sender := [16]byte{9}
	var mu sync.Mutex
	seen := map[uint64]bool{}
	var wg sync.WaitGroup
	for i := 0; i < stores; i++ {
		s, err := Open(Options{Dir: dir, ForceFile: true}) // separate instances ~ processes
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			var last uint64
			for j := 0; j < per; j++ {
				n, err := s.NextSendCounter()
				if err != nil {
					t.Error(err)
					return
				}
				if n <= last {
					t.Errorf("not increasing: %d after %d", n, last)
				}
				last = n
				mu.Lock()
				if seen[n] {
					t.Errorf("duplicate counter %d", n)
				}
				seen[n] = true
				mu.Unlock()
				if err := s.SetLastCounter(sender, n); err != nil {
					t.Error(err)
					return
				}
				// A stale SaveState must not lower counters.
				if err := s.SaveState(&State{RelayURL: "r", SendCounter: 1, LastCounters: map[string]uint64{fmt.Sprintf("%x", sender): 1}}); err != nil {
					t.Error(err)
					return
				}
				if st, err := s.LoadState(); err != nil || st.LastCounter(sender) < n || st.SendCounter < n {
					t.Errorf("counters decreased: %+v %v", st, err)
				}
			}
		}(i, s)
	}
	wg.Wait()
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	st, _ := s.LoadState()
	if st.SendCounter != stores*per || len(seen) != stores*per || st.LastCounter(sender) != stores*per {
		t.Fatalf("send=%d seen=%d last=%d", st.SendCounter, len(seen), st.LastCounter(sender))
	}
	// fn error -> nothing written.
	boom := errors.New("boom")
	if err := s.UpdateState(func(st *State) error { st.RelayURL = "x"; return boom }); err != boom {
		t.Fatal(err)
	}
	if st, _ = s.LoadState(); st.RelayURL != "r" {
		t.Fatalf("failed update persisted: %q", st.RelayURL)
	}
}

func TestCorruptIdentity(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	os.WriteFile(filepath.Join(dir, "identity.key"), []byte("garbage"), 0o600)
	if _, err := s.LoadIdentity(); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	} else if strings.Contains(err.Error(), "garbage") {
		t.Fatal("error leaks content")
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	st, err := s.LoadState()
	if err != nil || st.SendCounter != 0 || st.RelayURL != "" {
		t.Fatalf("empty: %+v %v", st, err)
	}
	st.RelayURL = "https://relay.example"
	st.GroupID = [16]byte{1, 2, 3, 15: 9}
	st.RosterBlob = []byte{0, 1, 2, 255}
	sender := [16]byte{7}
	st.SetLastCounter(sender, 42)
	st.SetLastCounter(sender, 10) // must not decrease
	st.NextSendCounter()
	st.NextSendCounter()
	if err := s.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if p := perm(t, filepath.Join(dir, "state.json")); p != 0o600 {
			t.Errorf("state perm %o", p)
		}
	}
	got, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if got.RelayURL != st.RelayURL || got.GroupID != st.GroupID || string(got.RosterBlob) != string(st.RosterBlob) ||
		got.LastCounter(sender) != 42 || got.SendCounter != 2 {
		t.Fatalf("mismatch %+v", got)
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover %s", e.Name())
		}
	}
	// Overwrite keeps 0600 and new content.
	st.SendCounter = 99
	if err := s.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.LoadState(); got.SendCounter != 99 {
		t.Fatal("overwrite failed")
	}
}

func TestCorruptState(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	for _, c := range []string{"{", `{"group_id":"zz"}`, `{"group_id":"00"}`, `{"roster_blob":"!!"}`} {
		os.WriteFile(filepath.Join(dir, "state.json"), []byte(c), 0o600)
		if _, err := s.LoadState(); err == nil {
			t.Errorf("accepted %q", c)
		}
	}
}

func TestDeviceIDMatchesHash(t *testing.T) {
	id, _ := Generate()
	if id.DeviceID() != roster.DeviceID(id.PublicKey()) {
		t.Fatal("device id differs from roster.DeviceID")
	}
}

func TestStaleRosterNeverRollsBack(t *testing.T) {
	dir := t.TempDir()
	gid := [16]byte{1}
	daemon, _ := Open(Options{Dir: dir, ForceFile: true})
	cli, _ := Open(Options{Dir: dir, ForceFile: true})
	if err := daemon.SaveState(&State{RelayURL: "r", GroupID: gid, RosterBlob: []byte("v1"), RosterVersion: 1}); err != nil {
		t.Fatal(err)
	}
	mem, _ := daemon.LoadState() // daemon's in-memory copy: v1
	// A CLI writes a newer roster (ecb pair / devices rm).
	if err := cli.UpdateState(func(s *State) error { s.RosterBlob, s.RosterVersion = []byte("v2"), 2; return nil }); err != nil {
		t.Fatal(err)
	}
	// The daemon persists counters with its stale copy via SaveState.
	mem.SetLastCounter([16]byte{5}, 3)
	if err := daemon.SaveState(mem); err != nil {
		t.Fatal(err)
	}
	st, _ := cli.LoadState()
	if string(st.RosterBlob) != "v2" || st.RosterVersion != 2 {
		t.Fatalf("roster rolled back to %q v%d", st.RosterBlob, st.RosterVersion)
	}
	if st.LastCounter([16]byte{5}) != 3 {
		t.Fatal("counter lost")
	}
	// Writers that do not bump the version cannot replace it either.
	if err := cli.UpdateState(func(s *State) error { s.RosterBlob = []byte("x"); return nil }); err != nil {
		t.Fatal(err)
	}
	if st, _ = cli.LoadState(); string(st.RosterBlob) != "v2" {
		t.Fatalf("unversioned write replaced roster: %q", st.RosterBlob)
	}
	// A different group (re-init) may replace it.
	if err := cli.SaveState(&State{RelayURL: "r", GroupID: [16]byte{2}, RosterBlob: []byte("g2"), RosterVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if st, _ = cli.LoadState(); string(st.RosterBlob) != "g2" {
		t.Fatalf("new group not stored: %q", st.RosterBlob)
	}
}

func TestLegacyStateWithoutRosterVersionStillLoads(t *testing.T) {
	dir := t.TempDir()
	old := `{"relay_url":"r","group_id":"01010101010101010101010101010101","roster_blob":"djE="}`
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := Open(Options{Dir: dir, ForceFile: true})
	st, err := s.LoadState()
	if err != nil || st.RosterVersion != 0 || string(st.RosterBlob) != "v1" {
		t.Fatalf("%+v %v", st, err)
	}
	if err := s.UpdateState(func(s *State) error { s.RosterBlob, s.RosterVersion = []byte("v2"), 2; return nil }); err != nil {
		t.Fatal(err)
	}
	if st, _ = s.LoadState(); string(st.RosterBlob) != "v2" {
		t.Fatal("legacy state could not be upgraded")
	}
}

func TestFileBackendNeverUsesOSKeyring(t *testing.T) {
	for _, o := range []Options{{Backend: BackendFile}, {ForceFile: true}} {
		o.Dir = t.TempDir()
		s, err := Open(o)
		if err != nil {
			t.Fatal(err)
		}
		if s.kr != nil {
			t.Fatalf("%+v: file backend holds a keyring (%T)", o, s.kr)
		}
	}
	t.Setenv(EnvBackend, "file")
	s, _ := Open(Options{Dir: t.TempDir()})
	if s.kr != nil {
		t.Fatal("ECB_KEYSTORE=file holds a keyring")
	}
	t.Setenv(EnvBackend, "auto")
	if s, _ = Open(Options{Dir: t.TempDir()}); s.kr == nil {
		t.Fatal("auto lost the OS keyring")
	}
}
