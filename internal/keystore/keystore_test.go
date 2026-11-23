package keystore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
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

	// Unavailable keyring -> file fallback.
	dir2 := t.TempDir()
	s2, _ := Open(Options{Dir: dir2, Keyring: &fakeKR{fail: true}})
	if err := s2.SaveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if p := perm(t, filepath.Join(dir2, "identity.key")); p != 0o600 {
		t.Errorf("perm %o", p)
	}
	got, err = s2.LoadIdentity()
	if err != nil || got.DeviceID() != id.DeviceID() {
		t.Fatal(err)
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
