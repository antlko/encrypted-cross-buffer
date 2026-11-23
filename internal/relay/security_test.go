package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/frame"
)

func newTestServer(t *testing.T, mod func(*Config)) *Server {
	t.Helper()
	cfg := Config{DataDir: t.TempDir(), EnrollToken: "0123456789abcdef0123"}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestClientIP(t *testing.T) {
	req := func(remote string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	untrusted := newTestServer(t, nil)
	trusted := newTestServer(t, func(c *Config) { c.TrustProxyHeaders = true })
	cases := []struct {
		name   string
		s      *Server
		remote string
		hdr    map[string]string
		want   string
	}{
		{"untrusted ignores spoofed header", untrusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "9.9.9.9"},
		{"trusted uses CF header", trusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "1.2.3.4"},
		{"trusted ignores XFF", trusted, "9.9.9.9:1", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "9.9.9.9"},
		{"hostname rejected", trusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "localhost"}, "9.9.9.9"},
		{"garbage rejected", trusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "1.2.3.4, evil"}, "9.9.9.9"},
		{"ipv6 zone stripped", trusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "fe80::1%eth0"}, "fe80::/64"},
		{"ipv4-mapped normalised", trusted, "9.9.9.9:1", map[string]string{"CF-Connecting-IP": "::ffff:1.2.3.4"}, "1.2.3.4"},
		{"remote ipv6 keyed by /64", untrusted, "[2001:db8::1]:5", nil, "2001:db8::/64"},
		{"same /64 shares a key", untrusted, "[2001:db8::ffff:1:2:3]:5", nil, "2001:db8::/64"},
		{"other /64 differs", untrusted, "[2001:db8:0:1::1]:5", nil, "2001:db8:0:1::/64"},
	}
	for _, c := range cases {
		if got := c.s.clientIP(req(c.remote, c.hdr)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestLimiterBoundedAndLRU(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(Rate{Burst: 1, Every: time.Hour}, func() time.Time { return now })
	for i := 0; i < maxLimiterKeys+500; i++ {
		now = now.Add(time.Millisecond)
		l.allow("k" + strconv.Itoa(i))
	}
	if len(l.m) > maxLimiterKeys {
		t.Fatalf("limiter map unbounded: %d", len(l.m))
	}
	if _, ok := l.m["k0"]; ok {
		t.Fatal("oldest key not evicted")
	}
	if _, ok := l.m["k"+strconv.Itoa(maxLimiterKeys+499)]; !ok {
		t.Fatal("newest key evicted")
	}
}

// Spoofed header values must never cause a lookup: a unique hostname per
// request would otherwise create unlimited limiter keys.
func TestSpoofedHostnameHeadersShareOneBucket(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.TrustProxyHeaders = true })
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("POST", "/v1/groups", nil)
		r.RemoteAddr = "9.9.9.9:1"
		r.Header.Set("CF-Connecting-IP", "host"+strconv.Itoa(i)+".invalid")
		r.Header.Set("X-Forwarded-For", "10.0."+strconv.Itoa(i)+".1")
		s.Handler().ServeHTTP(httptest.NewRecorder(), r)
	}
	if n := len(s.lim.enroll.m); n != 1 {
		t.Fatalf("expected a single limiter key, got %d", n)
	}
}

type postEnv struct {
	s         *Server
	gid       string
	gidB      [16]byte
	sk, sk2   ed25519.PrivateKey
	pub, pub2 pubKey
	tok       string
}

func newPostEnv(t *testing.T) *postEnv {
	t.Helper()
	s := newTestServer(t, nil)
	e := &postEnv{s: s}
	p1, sk1, _ := ed25519.GenerateKey(rand.Reader)
	p2, sk2, _ := ed25519.GenerateKey(rand.Reader)
	e.sk, e.sk2 = sk1, sk2
	copy(e.pub[:], p1)
	copy(e.pub2[:], p2)
	e.gidB = [16]byte{7}
	e.gid = hex.EncodeToString(e.gidB[:])
	if err := s.groups.create(e.gid, e.pub, []byte("r1"), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.groups.publish(e.gid, e.pub, 2, []byte("r2"), []pubKey{e.pub, e.pub2}); err != nil {
		t.Fatal(err)
	}
	var ok bool
	e.tok, ok = s.auth.issue(e.gid, e.pub)
	if !ok {
		t.Fatal("issue")
	}
	return e
}

func (e *postEnv) frame(t *testing.T, ct int) []byte {
	var buf bytes.Buffer
	h := frame.Header{GroupID: e.gidB, SenderID: e.pub.deviceID(), Counter: 1, CreatedMs: time.Now().UnixMilli(), CtLen: uint64(ct)}
	w, err := frame.NewWriter(&buf, e.sk, h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(make([]byte, ct))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (e *postEnv) post(body []byte, cl int64) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/items", bytes.NewReader(body))
	r.ContentLength = cl
	r.Header.Set("Authorization", "Bearer "+e.tok)
	w := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(w, r)
	return w
}

func spoolEntries(t *testing.T, dir string) (n int) {
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() && filepath.Base(p) != "groups.json" && filepath.Ext(p) == "" {
			n++
		}
		return nil
	})
	return
}

func TestPostItemOK(t *testing.T) {
	e := newPostEnv(t)
	f := e.frame(t, 100)
	if w := e.post(f, int64(len(f))); w.Code != 200 {
		t.Fatalf("code %d %s", w.Code, w.Body)
	}
	if evs, _ := e.s.hub.since(e.gid, 0, ""); len(evs) != 1 || evs[0].Size != int64(len(f)) {
		t.Fatalf("events %+v", evs)
	}
}

// Roster publish removing the sender between verification and commit must
// reject the upload, store nothing and emit no event.
func TestPostItemMembershipRecheckAtCommit(t *testing.T) {
	e := newPostEnv(t)
	e.s.afterVerify = func() {
		if err := e.s.groups.publish(e.gid, e.pub2, 3, []byte("r3"), []pubKey{e.pub2}); err != nil {
			t.Error(err)
		}
	}
	f := e.frame(t, 100)
	w := e.post(f, int64(len(f)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("removed sender upload not rejected: %d %s", w.Code, w.Body)
	}
	if e.s.items.latest[e.gid] != nil {
		t.Fatal("item stored")
	}
	if n := spoolEntries(t, e.s.cfg.DataDir); n != 0 {
		t.Fatalf("%d spool files left", n)
	}
	if evs, _ := e.s.hub.since(e.gid, 0, ""); len(evs) != 0 {
		t.Fatalf("event emitted: %+v", evs)
	}
}

func TestPostItemRejectsContentLengthMismatch(t *testing.T) {
	e := newPostEnv(t)
	f := e.frame(t, 100)
	// Content-Length larger than the frame: body ends early.
	if w := e.post(f, int64(len(f))+10); w.Code == 200 {
		t.Fatal("accepted CL > frame")
	}
	// Content-Length smaller than the frame: truncated by MaxBytesReader.
	if w := e.post(f, int64(len(f))-1); w.Code == 200 {
		t.Fatal("accepted CL < frame")
	}
	if e.s.items.latest[e.gid] != nil {
		t.Fatal("item stored")
	}
}

func TestPairBurnLimitedPerIP(t *testing.T) {
	e := newPostEnv(t)
	ok, limited := 0, 0
	for i := 0; i < 40; i++ {
		r := httptest.NewRequest("DELETE", "/v1/pair/5", nil)
		r.RemoteAddr = "9.9.9.9:1"
		w := httptest.NewRecorder()
		e.s.Handler().ServeHTTP(w, r)
		switch w.Code {
		case 204:
			ok++
		case 429:
			limited++
		}
	}
	if ok != 10 || limited != 30 {
		t.Fatalf("ok=%d limited=%d", ok, limited)
	}
}

// A revoke that lands between authed() and hub.track() must still end the
// connection.
func TestConnCtxRecheckAfterTrack(t *testing.T) {
	e := newPostEnv(t)
	sess := e.s.auth.lookup(e.tok)
	if err := e.s.groups.publish(e.gid, e.pub, 3, []byte("r3"), []pubKey{e.pub2}); err != nil {
		t.Fatal(err)
	}
	ctx, done := e.s.connCtx(httptest.NewRequest("GET", "/", nil), sess)
	defer done()
	select {
	case <-ctx.Done():
		if context.Cause(ctx) != errRevoked {
			t.Fatalf("cause %v", context.Cause(ctx))
		}
	default:
		t.Fatal("connection of a removed device stays open")
	}
}
