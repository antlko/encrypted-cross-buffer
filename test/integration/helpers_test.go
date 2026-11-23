package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
	"github.com/antlko/encrypted-cross-buffer/internal/roster"
)

const enrollToken = "test-enroll-token-0123456789"

// fakeClock is shared by the relay and the clients so TTL tests can jump ahead.
type fakeClock struct{ off atomic.Int64 }

func (c *fakeClock) Now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *fakeClock) Advance(d time.Duration) { c.off.Add(int64(d)) }

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// hitHandler counts requests per path and can hide the websocket endpoint.
type hitHandler struct {
	h       http.Handler
	mu      sync.Mutex
	hits    map[string]int
	blockWS atomic.Bool
}

func (h *hitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.hits[r.URL.Path]++
	h.mu.Unlock()
	if r.URL.Path == "/v1/ws" && h.blockWS.Load() {
		http.NotFound(w, r)
		return
	}
	h.h.ServeHTTP(w, r)
}

func (h *hitHandler) count(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

type env struct {
	t     *testing.T
	srv   *relay.Server
	ts    *httptest.Server
	hits  *hitHandler
	clock *fakeClock
	dir   string
	logs  *syncBuf
	cfg   relay.Config
}

func newEnv(t *testing.T, opts ...func(*relay.Config)) *env {
	t.Helper()
	return startEnv(t, t.TempDir(), opts...)
}

func startEnv(t *testing.T, dir string, opts ...func(*relay.Config)) *env {
	t.Helper()
	e := &env{t: t, clock: &fakeClock{}, dir: dir, logs: &syncBuf{}}
	e.cfg = relay.Config{
		Addr: ":0", DataDir: dir, EnrollToken: enrollToken,
		MaxItemBytes: 32 << 20, ItemTTL: 10 * time.Minute,
		Limits: relay.DefaultRateLimits(), Now: e.clock.Now,
	}
	for _, o := range opts {
		o(&e.cfg)
	}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := relay.New(e.cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.hits = &hitHandler{h: srv.Handler(), hits: map[string]int{}}
	e.ts = httptest.NewServer(e.hits)
	t.Cleanup(e.stop)
	return e
}

// stop is idempotent: close ws/long-polls first, then the listener.
func (e *env) stop() {
	e.srv.Close()
	e.ts.Close()
}

type dev struct {
	name  string
	id    *keystore.Identity
	state *keystore.State
	c     *client.Client
}

type rosterBox struct {
	mu sync.RWMutex
	r  *roster.Roster
}

func (b *rosterBox) Roster() (*roster.Roster, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.r, nil
}
func (b *rosterBox) set(r *roster.Roster) { b.mu.Lock(); b.r = r; b.mu.Unlock() }

type grp struct {
	e    *env
	gid  [16]byte
	box  *rosterBox
	devs []*dev
}

func (e *env) newDev(name string, gid [16]byte, box client.RosterProvider, mod ...func(*client.Config)) *dev {
	e.t.Helper()
	id, err := keystore.Generate()
	if err != nil {
		e.t.Fatal(err)
	}
	return e.attach(name, id, gid, box, mod...)
}

func (e *env) attach(name string, id *keystore.Identity, gid [16]byte, box client.RosterProvider, mod ...func(*client.Config)) *dev {
	e.t.Helper()
	st := &keystore.State{GroupID: gid}
	cfg := client.Config{
		BaseURL: e.ts.URL, Identity: id, GroupID: gid, Roster: box, State: st,
		Now: e.clock.Now, BackoffMin: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond,
		PollWait: 2 * time.Second,
	}
	for _, m := range mod {
		m(&cfg)
	}
	c, err := client.New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return &dev{name: name, id: id, state: st, c: c}
}

// newGroup creates a group with n devices; devs[0] creates it and signs every
// roster version. Roster versions are 1..n.
func (e *env) newGroup(n int, mod ...func(*client.Config)) *grp {
	e.t.Helper()
	gid := [16]byte{}
	copy(gid[:], randBytes(16))
	g := &grp{e: e, gid: gid, box: &rosterBox{}}
	a := e.newDev("A", gid, g.box, mod...)
	g.devs = append(g.devs, a)
	r, err := roster.NewGenesis(gid, roster.NewEntry("A", a.id.Recipient(), a.id.PublicKey(), 1), a.id.Ed25519)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := ctxT(e.t, 20*time.Second)
	if err := a.c.CreateGroup(ctx, enrollToken, r); err != nil {
		e.t.Fatal(err)
	}
	for i := 1; i < n; i++ {
		d := e.newDev(string(rune('A'+i)), gid, g.box, mod...)
		g.devs = append(g.devs, d)
		r, err = r.Add(a.id.DeviceID(), roster.NewEntry(d.name, d.id.Recipient(), d.id.PublicKey(), 1))
		if err != nil {
			e.t.Fatal(err)
		}
		if err := r.Sign(a.id.Ed25519); err != nil {
			e.t.Fatal(err)
		}
		if err := a.c.PublishRoster(ctx, r); err != nil {
			e.t.Fatal(err)
		}
	}
	g.box.set(r)
	return g
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	// Not security sensitive (test fixtures), but must differ between runs.
	for i := 0; i < n; i += 8 {
		v := uint64(time.Now().UnixNano()) ^ uint64(counter.Add(1))*0x9e3779b97f4a7c15
		for j := 0; j < 8 && i+j < n; j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
	return b
}

var counter atomic.Uint64

// ---- raw HTTP helpers ------------------------------------------------------

func (e *env) rawJSON(method, path, token string, in any, hdr map[string]string) (int, []byte) {
	e.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// rawToken performs the challenge-response by hand and returns a token.
func (e *env) rawToken(id *keystore.Identity, gid [16]byte) string {
	e.t.Helper()
	code, tok := e.rawAuth(id, gid, nil)
	if code != 200 {
		e.t.Fatalf("auth status %d", code)
	}
	return tok
}

// rawAuth: mutate may alter the signature input to test failures.
func (e *env) rawAuth(id *keystore.Identity, gid [16]byte, mutate func(nonce string, sig []byte) (string, []byte)) (int, string) {
	e.t.Helper()
	gh := hexs(gid[:])
	code, b := e.rawJSON("POST", "/v1/auth/challenge", "", map[string]string{"group_id": gh}, nil)
	if code != 200 {
		return code, ""
	}
	var ch struct{ Nonce string }
	_ = json.Unmarshal(b, &ch)
	nonceRaw := b64d(ch.Nonce)
	sig := ed25519.Sign(id.Ed25519, relay.AuthMessage(nonceRaw, gid))
	nonce := ch.Nonce
	if mutate != nil {
		nonce, sig = mutate(nonce, sig)
	}
	code, b = e.rawJSON("POST", "/v1/auth/token", "", map[string]any{
		"group_id": gh, "pub": []byte(id.PublicKey()), "nonce": nonce, "sig": sig}, nil)
	var tr struct{ Token string }
	_ = json.Unmarshal(b, &tr)
	return code, tr.Token
}

func spoolFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(filepath.Join(dir, "items"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// proxy is a TCP forwarder whose connections can be cut on demand (httptest
// cannot close hijacked websocket connections).
type proxy struct {
	addr   string
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	target string
}

func newProxy(t *testing.T, target string) *proxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{addr: ln.Addr().String(), ln: ln, target: target}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, u)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(u, c); u.Close() }()
			go func() { _, _ = io.Copy(c, u); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close(); p.dropAll() })
	return p
}

func (p *proxy) dropAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = nil
}
