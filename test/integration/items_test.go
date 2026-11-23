package integration

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/envelope"
	"github.com/antlko/encrypted-cross-buffer/internal/frame"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
)

// buildFrame produces a signed frame whose "ciphertext" is arbitrary bytes
// (the relay never decrypts).
func buildFrame(t *testing.T, sk ed25519.PrivateKey, h frame.Header, ct []byte) []byte {
	t.Helper()
	h.CtLen = uint64(len(ct))
	var b bytes.Buffer
	w, err := frame.NewWriter(&b, sk, h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(ct)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func (e *env) postFrame(token string, body []byte) int {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/items", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestOversize413AndNoTempFiles(t *testing.T) {
	e := newEnv(t, func(c *relay.Config) { c.MaxItemBytes = 1 << 20 })
	g := e.newGroup(2)
	a := g.devs[0]
	tok := e.rawToken(a.id, g.gid)
	h := frame.Header{GroupID: g.gid, SenderID: a.id.DeviceID(), Counter: 1, CreatedMs: e.clock.Now().UnixMilli()}

	if code := e.postFrame(tok, buildFrame(t, a.id.Ed25519, h, make([]byte, 2<<20))); code != 413 {
		t.Fatalf("oversize: %d", code)
	}
	// Missing Content-Length (chunked) is refused.
	pr, pw := io.Pipe()
	go func() { _, _ = pw.Write(buildFrame(t, a.id.Ed25519, h, []byte("x"))); pw.Close() }()
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/items", pr)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 411 {
		t.Fatalf("chunked upload: %d", resp.StatusCode)
	}
	// Header claims more ciphertext than the body carries: rejected, temp file removed.
	full := buildFrame(t, a.id.Ed25519, h, make([]byte, 64<<10))
	if code := e.postFrame(tok, full[:len(full)-1000]); code != 400 {
		t.Fatalf("truncated: %d", code)
	}
	if files := spoolFiles(t, e.dir); len(files) != 0 {
		t.Fatalf("leftover files: %v", files)
	}
}

func TestRejectedItemsStoreNothing(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	outsider := e.newDev("X", g.gid, g.box)
	tok := e.rawToken(a.id, g.gid)
	now := e.clock.Now().UnixMilli()
	base := frame.Header{GroupID: g.gid, SenderID: a.id.DeviceID(), Counter: 1, CreatedMs: now}
	ct := bytes.Repeat([]byte("c"), 4096)
	mod := func(f func(*frame.Header)) frame.Header { h := base; f(&h); return h }

	good := buildFrame(t, a.id.Ed25519, base, ct)
	tampered := append([]byte(nil), good...)
	tampered[frame.HeaderSize+10] ^= 0xff // ciphertext changed after signing
	badSig := append([]byte(nil), good...)
	badSig[len(badSig)-1] ^= 1

	cases := []struct {
		name string
		body []byte
		want int
	}{
		{"wrong sender (device B header, A token)", buildFrame(t, b.id.Ed25519, mod(func(h *frame.Header) { h.SenderID = b.id.DeviceID() }), ct), 403},
		{"unknown sender", buildFrame(t, outsider.id.Ed25519, mod(func(h *frame.Header) { h.SenderID = outsider.id.DeviceID() }), ct), 403},
		{"wrong group", buildFrame(t, a.id.Ed25519, mod(func(h *frame.Header) { h.GroupID = [16]byte{1} }), ct), 403},
		{"sender id of A, signed by B", buildFrame(t, b.id.Ed25519, base, ct), 400},
		{"tampered ciphertext", tampered, 400},
		{"bad signature", badSig, 400},
		{"trailing data", append(append([]byte(nil), good...), 'x'), 400},
		{"stale created_ms", buildFrame(t, a.id.Ed25519, mod(func(h *frame.Header) { h.CreatedMs = now - int64(time.Hour/time.Millisecond) }), ct), 400},
		{"future created_ms", buildFrame(t, a.id.Ed25519, mod(func(h *frame.Header) { h.CreatedMs = now + int64(time.Hour/time.Millisecond) }), ct), 400},
		{"garbage", bytes.Repeat([]byte("z"), 500), 400},
	}
	for _, c := range cases {
		if code := e.postFrame(tok, c.body); code != c.want {
			t.Errorf("%s: got %d want %d", c.name, code, c.want)
		}
	}
	if files := spoolFiles(t, e.dir); len(files) != 0 {
		t.Fatalf("rejected items left files: %v", files)
	}
	// And the good one is accepted, replacing nothing else.
	if code := e.postFrame(tok, good); code != 200 {
		t.Fatalf("good frame: %d", code)
	}
	if files := spoolFiles(t, e.dir); len(files) != 1 {
		t.Fatalf("want exactly 1 stored item, got %v", files)
	}
}

func TestLatestOnlyAndExpiry404(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx := ctxT(t, 30*time.Second)

	r1, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.c.FetchItem(ctx, r1.ID); !client.IsStatus(err, 404) {
		t.Fatalf("replaced item still served: %v", err)
	}
	if n := len(spoolFiles(t, e.dir)); n != 1 {
		t.Fatalf("latest-only violated: %d files", n)
	}
	e.clock.Advance(10*time.Minute + time.Second)
	if _, err := b.c.FetchItem(ctx, r2.ID); !client.IsStatus(err, 404) {
		t.Fatalf("expired item: %v", err)
	}
	if n := len(spoolFiles(t, e.dir)); n != 0 {
		t.Fatalf("expired file not deleted on read: %d", n)
	}
	// The sweeper path too.
	e2 := newEnv(t)
	g2 := e2.newGroup(2)
	if _, err := g2.devs[0].c.SendItem(ctx, envelope.CTypeText, []byte("x")); err != nil {
		t.Fatal(err)
	}
	e2.clock.Advance(11 * time.Minute)
	e2.srv.Sweep()
	if n := len(spoolFiles(t, e2.dir)); n != 0 {
		t.Fatalf("sweeper left %d files", n)
	}
	// Files are private.
	_ = filepath.WalkDir(e.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == e.dir { // the data dir itself is created by the test harness
			return nil
		}
		fi, _ := d.Info()
		if d.IsDir() && fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("dir %s mode %v", p, fi.Mode())
		}
		if !d.IsDir() && fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("file %s mode %v", p, fi.Mode())
		}
		return nil
	})
}

// TestRelayMemoryConstant streams a ~30 MiB frame to the relay through
// frame.NewWriter over a generator (the body is never held in RAM) and checks
// that the heap does not grow with the item size.
//
// Method: relay and test share one process. After a warm-up upload (so
// connections and pools exist) and runtime.GC(), the baseline is
// runtime.MemStats.HeapInuse. During the 30 MiB upload a goroutine samples
// HeapInuse every millisecond; the assertion is max(sample) - baseline < 8 MiB.
// HeapInuse counts live objects plus not-yet-collected garbage, so it is an
// upper bound of what the relay retains. A relay doing io.ReadAll would peak
// at >= 30 MiB.
func TestRelayMemoryConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	e := newEnv(t)
	g := e.newGroup(2)
	a := g.devs[0]
	tok := e.rawToken(a.id, g.gid)
	const ctLen = 30 << 20

	upload := func(n uint64) int {
		pr, pw := io.Pipe()
		h := frame.Header{GroupID: g.gid, SenderID: a.id.DeviceID(), Counter: 1,
			CreatedMs: e.clock.Now().UnixMilli(), CtLen: n}
		go func() {
			fw, err := frame.NewWriter(pw, a.id.Ed25519, h)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			chunk := bytes.Repeat([]byte{0xA5}, 64<<10)
			for left := n; left > 0; {
				k := min(uint64(len(chunk)), left)
				if _, err := fw.Write(chunk[:k]); err != nil {
					pw.CloseWithError(err)
					return
				}
				left -= k
			}
			pw.CloseWithError(fw.Close())
		}()
		req, _ := http.NewRequest("POST", e.ts.URL+"/v1/items", pr)
		req.ContentLength = int64(frame.HeaderSize+frame.SigSize) + int64(n)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if code := upload(1 << 20); code != 200 { // warm-up
		t.Fatalf("warm-up: %d", code)
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse

	var (
		mu   sync.Mutex
		peak = base
		stop = make(chan struct{})
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				mu.Lock()
				peak = max(peak, m.HeapInuse)
				mu.Unlock()
			}
		}
	}()
	code := upload(ctLen)
	close(stop)
	<-done
	if code != 200 {
		t.Fatalf("30 MiB upload: %d", code)
	}
	mu.Lock()
	growth := int64(peak) - int64(base)
	mu.Unlock()
	t.Logf("HeapInuse baseline=%d KiB peak=%d KiB growth=%d KiB", base>>10, peak>>10, growth>>10)
	if growth >= 8<<20 {
		t.Fatalf("heap grew by %d bytes during a %d byte upload", growth, ctLen)
	}
	files := spoolFiles(t, e.dir)
	if len(files) != 1 {
		t.Fatalf("spool: %v", files)
	}
	if fi, _ := os.Stat(files[0]); fi.Size() != int64(frame.HeaderSize+frame.SigSize+ctLen) {
		t.Fatalf("stored size %d", fi.Size())
	}
}
