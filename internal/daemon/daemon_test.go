package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/clip"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

const enrollToken = "test-enroll-token-0123456789"

// nullKeyring keeps tests away from the real OS keychain.
type nullKeyring struct{}

func (nullKeyring) Get() (string, error) { return "", keystore.ErrNotFound }
func (nullKeyring) Set(string) error     { return errors.New("no keychain in tests") }
func (nullKeyring) Delete() error        { return nil }

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type device struct {
	name    string
	id      *keystore.Identity
	store   *keystore.Store
	clipDir string
	cb      clip.Clipboard
	d       *Daemon
	logs    *syncBuf
	done    chan struct{}
	err     error
	cancel  context.CancelFunc
}

type world struct {
	t   *testing.T
	url string
	gid [16]byte
	r   *roster.Roster
	cl  *client.Client // device 0's client for roster publication
	dev []*device
}

func newWorld(t *testing.T, n int) *world {
	t.Helper()
	cfg := relay.Config{Addr: ":0", DataDir: t.TempDir(), EnrollToken: enrollToken, MaxItemBytes: 32 << 20,
		ItemTTL: 10 * time.Minute, Limits: relay.DefaultRateLimits()}
	srv, err := relay.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { srv.Close(); ts.Close() })
	w := &world{t: t, url: ts.URL, gid: [16]byte{4, 2}}
	for i := 0; i < n; i++ {
		store, err := keystore.Open(keystore.Options{Dir: t.TempDir(), Backend: keystore.BackendFile, Keyring: nullKeyring{}})
		if err != nil {
			t.Fatal(err)
		}
		id, _, err := store.LoadOrCreateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		cd := t.TempDir()
		cb, _ := clip.NewFile(cd)
		w.dev = append(w.dev, &device{name: string(rune('a' + i)), id: id, store: store, clipDir: cd, cb: cb, logs: &syncBuf{}})
	}
	d0 := w.dev[0]
	w.r, err = roster.NewGenesis(w.gid, roster.NewEntry("a", d0.id.Recipient(), d0.id.PublicKey(), 1), d0.id.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	w.cl, err = client.New(client.Config{BaseURL: w.url, Identity: d0.id, GroupID: w.gid,
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return w.r, nil })})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := w.cl.CreateGroup(ctx, enrollToken, w.r); err != nil {
		t.Fatal(err)
	}
	for _, d := range w.dev[1:] {
		w.r, err = w.r.Add(d0.id.DeviceID(), roster.NewEntry(d.name, d.id.Recipient(), d.id.PublicKey(), 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.r.Sign(d0.id.Ed25519); err != nil {
			t.Fatal(err)
		}
		if err := w.cl.PublishRoster(ctx, w.r); err != nil {
			t.Fatal(err)
		}
	}
	blob, _ := w.r.Seal()
	for _, d := range w.dev {
		if err := d.store.SaveState(&keystore.State{RelayURL: w.url, GroupID: w.gid, RosterBlob: blob}); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func (w *world) start(d *device) {
	w.t.Helper()
	dm, err := New(Options{Store: d.store, Identity: d.id, Clip: d.cb,
		Logger:   slog.New(slog.NewTextHandler(d.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Debounce: 50 * time.Millisecond, ConfigPoll: 50 * time.Millisecond, EchoWindow: -1,
		ClientTune: func(c *client.Config) { c.BackoffMin = 20 * time.Millisecond; c.BackoffMax = 100 * time.Millisecond }})
	if err != nil {
		w.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.d, d.cancel, d.done = dm, cancel, make(chan struct{})
	go func() { d.err = dm.Run(ctx); close(d.done) }()
	w.t.Cleanup(func() { cancel(); <-d.done })
	select {
	case <-dm.Ready():
	case <-time.After(10 * time.Second):
		w.t.Fatal("daemon not ready")
	}
}

func (w *world) startAll() {
	for _, d := range w.dev {
		w.start(d)
	}
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func readClip(d *device, k clip.Kind) []byte {
	b, _ := d.cb.Read(context.Background(), k)
	return b
}

func setMode(t *testing.T, d *device, mode string, mod ...func(*Config)) {
	t.Helper()
	c := DefaultConfig()
	c.Mode = mode
	for _, m := range mod {
		m(&c)
	}
	if err := SaveConfig(d.store.Dir(), c); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // > ConfigPoll
}

func pngBytes(n int) []byte {
	return append(append([]byte(nil), clip.PNGSignature...), bytes.Repeat([]byte{0xAB, 0xCD}, n)...)
}

func TestThreeDevicesNoLoop(t *testing.T) {
	w := newWorld(t, 3)
	w.startAll()
	text := []byte(strings.Repeat("line of text for the clipboard SECRETMARK-8841\n", 10000))
	start := time.Now()
	if err := w.dev[0].cb.Write(context.Background(), clip.KindText, text); err != nil {
		t.Fatal(err)
	}
	for _, d := range w.dev[1:] {
		waitFor(t, "delivery to "+d.name, 3*time.Second, func() bool { return bytes.Equal(readClip(d, clip.KindText), text) })
	}
	t.Logf("delivered to 2 devices in %v", time.Since(start))
	// Give an echo loop time to show itself.
	time.Sleep(1500 * time.Millisecond)
	if w.dev[0].d.Sent() != 1 || w.dev[1].d.Sent() != 0 || w.dev[2].d.Sent() != 0 {
		t.Fatalf("sent counts: %d %d %d", w.dev[0].d.Sent(), w.dev[1].d.Sent(), w.dev[2].d.Sent())
	}
	if w.dev[0].d.Applied() != 0 || w.dev[1].d.Applied() != 1 || w.dev[2].d.Applied() != 1 {
		t.Fatalf("applied counts: %d %d %d", w.dev[0].d.Applied(), w.dev[1].d.Applied(), w.dev[2].d.Applied())
	}
	// Reverse direction works as well.
	text2 := []byte("from device c")
	_ = w.dev[2].cb.Write(context.Background(), clip.KindText, text2)
	for _, d := range w.dev[:2] {
		waitFor(t, "reverse delivery to "+d.name, 3*time.Second, func() bool { return bytes.Equal(readClip(d, clip.KindText), text2) })
	}
	time.Sleep(800 * time.Millisecond)
	if w.dev[2].d.Sent() != 1 || w.dev[0].d.Sent() != 1 || w.dev[1].d.Sent() != 0 {
		t.Fatalf("sent counts after reverse: %d %d %d", w.dev[0].d.Sent(), w.dev[1].d.Sent(), w.dev[2].d.Sent())
	}
	// Logs must never contain clipboard content.
	for _, d := range w.dev {
		if strings.Contains(d.logs.String(), "SECRETMARK") || strings.Contains(d.logs.String(), "from device c") {
			t.Fatalf("clipboard content leaked into logs of %s", d.name)
		}
	}
}

func TestPNGRoundtripAndNonPNGRefused(t *testing.T) {
	w := newWorld(t, 2)
	w.startAll()
	img := pngBytes(50000)
	_ = w.dev[0].cb.Write(context.Background(), clip.KindPNG, img)
	waitFor(t, "png", 3*time.Second, func() bool { return bytes.Equal(readClip(w.dev[1], clip.KindPNG), img) })
	_ = w.dev[1].cb.Write(context.Background(), clip.KindPNG, []byte("this is not a png at all"))
	time.Sleep(700 * time.Millisecond)
	if w.dev[1].d.Sent() != 0 || !strings.Contains(w.dev[1].logs.String(), "not a PNG") {
		t.Fatal("non-PNG image must be refused with a notice")
	}
}

func TestSensitiveNeverSynced(t *testing.T) {
	w := newWorld(t, 2)
	w.startAll()
	if err := os.WriteFile(filepath.Join(w.dev[0].clipDir, "sensitive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = w.dev[0].cb.Write(context.Background(), clip.KindText, []byte("hunter2-password"))
	time.Sleep(900 * time.Millisecond)
	if w.dev[0].d.Sent() != 0 || w.dev[1].d.Applied() != 0 {
		t.Fatal("sensitive item was synced")
	}
	if !strings.Contains(w.dev[0].logs.String(), "sensitive") || strings.Contains(w.dev[0].logs.String(), "hunter2") {
		t.Fatal("expected a content-free notice")
	}
}

func TestOversizeSkipped(t *testing.T) {
	w := newWorld(t, 2)
	setMode(t, w.dev[0], ModeBoth, func(c *Config) { c.MaxTextBytes = 100; c.MaxImageBytes = 200 })
	w.startAll()
	_ = w.dev[0].cb.Write(context.Background(), clip.KindText, bytes.Repeat([]byte("x"), 101))
	time.Sleep(400 * time.Millisecond)
	_ = w.dev[0].cb.Write(context.Background(), clip.KindPNG, pngBytes(200))
	time.Sleep(900 * time.Millisecond)
	if w.dev[0].d.Sent() != 0 {
		t.Fatal("oversize item was sent")
	}
	l := w.dev[0].logs.String()
	if !strings.Contains(l, "larger than max_text_bytes") || !strings.Contains(l, "larger than max_image_bytes") {
		t.Fatalf("missing notices:\n%s", l)
	}
	// Within limits still works.
	_ = w.dev[0].cb.Write(context.Background(), clip.KindText, []byte("small"))
	waitFor(t, "small", 3*time.Second, func() bool { return string(readClip(w.dev[1], clip.KindText)) == "small" })
}

func TestModesAndLiveReload(t *testing.T) {
	w := newWorld(t, 3)
	w.startAll()
	a, b, c := w.dev[0], w.dev[1], w.dev[2]
	ctx := context.Background()

	// b: receive-only (does not send); c: send-only (does not apply).
	setMode(t, b, ModeReceiveOnly)
	setMode(t, c, ModeSendOnly)
	_ = b.cb.Write(ctx, clip.KindText, []byte("from b"))
	time.Sleep(900 * time.Millisecond)
	if b.d.Sent() != 0 {
		t.Fatal("receive-only device sent")
	}
	_ = a.cb.Write(ctx, clip.KindText, []byte("from a"))
	waitFor(t, "b applies", 3*time.Second, func() bool { return string(readClip(b, clip.KindText)) == "from a" })
	time.Sleep(300 * time.Millisecond)
	if string(readClip(c, clip.KindText)) == "from a" || c.d.Applied() != 0 {
		t.Fatal("send-only device applied an item")
	}
	_ = c.cb.Write(ctx, clip.KindText, []byte("from c"))
	waitFor(t, "a applies c", 3*time.Second, func() bool { return string(readClip(a, clip.KindText)) == "from c" })

	// paused: neither direction, switched while running.
	setMode(t, a, ModePaused)
	before := a.d.Sent()
	_ = a.cb.Write(ctx, clip.KindText, []byte("paused write"))
	_ = c.cb.Write(ctx, clip.KindText, []byte("c while a paused"))
	time.Sleep(900 * time.Millisecond)
	if a.d.Sent() != before || string(readClip(a, clip.KindText)) == "c while a paused" {
		t.Fatal("paused device synced")
	}
	// resume
	setMode(t, a, ModeBoth)
	_ = a.cb.Write(ctx, clip.KindText, []byte("after resume"))
	waitFor(t, "b after resume", 3*time.Second, func() bool { return string(readClip(b, clip.KindText)) == "after resume" })
}

func TestRevokedDeviceStopsReceivingAndExits(t *testing.T) {
	w := newWorld(t, 3)
	w.startAll()
	a, b, c := w.dev[0], w.dev[1], w.dev[2]
	ctx := context.Background()
	_ = a.cb.Write(ctx, clip.KindText, []byte("before revoke"))
	waitFor(t, "c before revoke", 3*time.Second, func() bool { return string(readClip(c, clip.KindText)) == "before revoke" })

	// a removes c (what `ecb devices rm c` does).
	cid := c.id.DeviceID()
	r2, err := w.r.Remove(cid)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Sign(a.id.Ed25519); err != nil {
		t.Fatal(err)
	}
	if err := w.cl.PublishRoster(ctx, r2); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
		if !errors.Is(c.err, ErrRevoked) {
			t.Fatalf("c exited with %v", c.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoked device kept running")
	}
	_ = a.cb.Write(ctx, clip.KindText, []byte("after revoke"))
	waitFor(t, "b after revoke", 3*time.Second, func() bool { return string(readClip(b, clip.KindText)) == "after revoke" })
	if string(readClip(c, clip.KindText)) == "after revoke" {
		t.Fatal("revoked device received the item")
	}
	// The daemon on a picks up the new roster (c no longer a recipient).
	waitFor(t, "a roster", 3*time.Second, func() bool { return a.d.Roster().Version >= 2 })
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadConfig(dir)
	if err != nil || c != DefaultConfig() {
		t.Fatalf("%v %+v", err, c)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(`{"mode":"nonsense"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if err := SetMode(dir, ModePaused); err != nil {
		t.Fatal(err)
	}
	c, _ = LoadConfig(dir)
	if c.Mode != ModePaused || c.MaxTextBytes != DefaultMaxText {
		t.Fatalf("%+v", c)
	}
	if err := SetMode(dir, "bogus"); err == nil {
		t.Fatal("bogus mode saved")
	}
}
