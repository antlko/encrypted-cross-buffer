package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/envelope"
	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
	"github.com/antlko/encrypted-cross-buffer/internal/roster"
)

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestCreateGroupEnroll(t *testing.T) {
	e := newEnv(t)
	gid := [16]byte{9}
	id, _ := keystore.Generate()
	r, _ := roster.NewGenesis(gid, roster.NewEntry("A", id.Recipient(), id.PublicKey(), 1), id.Ed25519)
	d := e.attach("A", id, gid, &rosterBox{r: r})
	ctx := ctxT(t, 20*time.Second)

	for i := 0; i < 5; i++ {
		err := d.c.CreateGroup(ctx, "wrong-token-wrong-token", r)
		if !client.IsStatus(err, 403) {
			t.Fatalf("attempt %d: want 403, got %v", i, err)
		}
	}
	// Rate limited now - even the right token is refused from this IP.
	if err := d.c.CreateGroup(ctx, "wrong-token-wrong-token", r); !client.IsStatus(err, 429) {
		t.Fatalf("want 429, got %v", err)
	}
	if err := d.c.CreateGroup(ctx, enrollToken, r); !client.IsStatus(err, 429) {
		t.Fatalf("want 429 for locked-out IP, got %v", err)
	}
}

func TestCreateGroupOKAndDuplicate(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	r, _ := g.box.Roster()
	if err := g.devs[0].c.CreateGroup(ctxT(t, 10*time.Second), enrollToken, r); !client.IsStatus(err, 409) {
		t.Fatalf("duplicate create: %v", err)
	}
	// Bad signature (signed by another key) is rejected.
	other, _ := keystore.Generate()
	gid := [16]byte{7}
	r2, _ := roster.NewGenesis(gid, roster.NewEntry("X", other.Recipient(), other.PublicKey(), 1), other.Ed25519)
	imposter := e.attach("X", other, gid, &rosterBox{r: r2})
	// Tamper: genesis for a different group than the client's.
	if err := imposter.c.CreateGroup(ctxT(t, 10*time.Second), enrollToken, r); err == nil {
		t.Fatal("foreign genesis accepted")
	}
	code, _ := e.rawJSON("POST", "/v1/groups", "", map[string]any{
		"group_id": "00000000000000000000000000000001", "ed25519_pub": []byte(other.PublicKey()),
		"roster_blob": []byte("x"), "roster_version": 1, "sig": make([]byte, 64)},
		map[string]string{"X-ECB-Enroll": enrollToken})
	if code != 403 {
		t.Fatalf("bad create sig: %d", code)
	}
}

func TestAuth(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a := g.devs[0]
	outsider, _ := keystore.Generate()

	if code, tok := e.rawAuth(a.id, g.gid, nil); code != 200 || tok == "" {
		t.Fatalf("member auth: %d", code)
	}
	if code, _ := e.rawAuth(outsider, g.gid, nil); code != 401 {
		t.Fatalf("outsider auth: %d", code)
	}
	// Signature by the wrong key / wrong nonce.
	if code, _ := e.rawAuth(a.id, g.gid, func(n string, s []byte) (string, []byte) {
		s[0] ^= 1
		return n, s
	}); code != 401 {
		t.Fatalf("bad sig: %d", code)
	}
	// Unknown group: same uniform answer as a bad signature.
	unknown := [16]byte{0xee}
	if code, _ := e.rawAuth(a.id, unknown, nil); code != 401 {
		t.Fatalf("unknown group: %d", code)
	}
	// Replay of a nonce: first use ok, second 401.
	gh := hexs(g.gid[:])
	_, b := e.rawJSON("POST", "/v1/auth/challenge", "", map[string]string{"group_id": gh}, nil)
	nonce := strings.Split(strings.Split(string(b), `"nonce":"`)[1], `"`)[0]
	sig := signAuth(a.id, nonce, g.gid)
	body := map[string]any{"group_id": gh, "pub": []byte(a.id.PublicKey()), "nonce": nonce, "sig": sig}
	if code, _ := e.rawJSON("POST", "/v1/auth/token", "", body, nil); code != 200 {
		t.Fatalf("first use: %d", code)
	}
	if code, _ := e.rawJSON("POST", "/v1/auth/token", "", body, nil); code != 401 {
		t.Fatalf("replayed nonce: %d", code)
	}
	// Nonce older than 60s is dead.
	_, b = e.rawJSON("POST", "/v1/auth/challenge", "", map[string]string{"group_id": gh}, nil)
	nonce = strings.Split(strings.Split(string(b), `"nonce":"`)[1], `"`)[0]
	e.clock.Advance(61 * time.Second)
	body = map[string]any{"group_id": gh, "pub": []byte(a.id.PublicKey()), "nonce": nonce, "sig": signAuth(a.id, nonce, g.gid)}
	if code, _ := e.rawJSON("POST", "/v1/auth/token", "", body, nil); code != 401 {
		t.Fatalf("expired nonce: %d", code)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	gh := hexs(g.gid[:])
	for _, c := range []struct{ m, p string }{
		{"POST", "/v1/items"}, {"GET", "/v1/items/" + strings.Repeat("a", 32)},
		{"GET", "/v1/ws"}, {"GET", "/v1/events"}, {"POST", "/v1/pair"},
		{"GET", "/v1/groups/" + gh + "/roster"}, {"POST", "/v1/groups/" + gh + "/roster"},
	} {
		for _, tok := range []string{"", "bogus-token"} {
			if code, _ := e.rawJSON(c.m, c.p, tok, nil, nil); code != 401 {
				t.Errorf("%s %s token=%q: %d", c.m, c.p, tok, code)
			}
		}
	}
	// ?token= is only honoured on /v1/ws.
	tok := e.rawToken(g.devs[0].id, g.gid)
	if code, _ := e.rawJSON("GET", "/v1/events?token="+tok, "", nil, nil); code != 401 {
		t.Fatalf("query token accepted outside ws: %d", code)
	}
}

// Relay-side token expiry (15 min) -> client re-authenticates transparently.
func TestTokenExpiryAutoRefresh(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx := ctxT(t, 30*time.Second)
	if _, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("one")); err != nil {
		t.Fatal(err)
	}
	before := e.hits.count("/v1/auth/token")
	e.clock.Advance(16 * time.Minute) // relay now considers a's token expired
	ref, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("two"))
	if err != nil {
		t.Fatalf("send after expiry: %v", err)
	}
	if e.hits.count("/v1/auth/token") <= before {
		t.Fatal("client did not re-authenticate")
	}
	if item, err := b.c.FetchItem(ctx, ref.ID); err != nil || string(item.Body) != "two" {
		t.Fatalf("fetch: %v", err)
	}
}

func TestProxyHeaders(t *testing.T) {
	post := func(e *env, ip string) int {
		code, _ := e.rawJSON("POST", "/v1/groups", "", map[string]any{}, map[string]string{
			"X-ECB-Enroll": "nope-nope-nope-nope", "CF-Connecting-IP": ip})
		return code
	}
	t.Run("trusted", func(t *testing.T) {
		e := newEnv(t, func(c *relay.Config) { c.TrustProxyHeaders = true })
		for i := 0; i < 5; i++ {
			post(e, "203.0.113.1")
		}
		if c := post(e, "203.0.113.1"); c != 429 {
			t.Fatalf("same forwarded ip: %d", c)
		}
		if c := post(e, "203.0.113.2"); c != 403 {
			t.Fatalf("other forwarded ip: %d", c)
		}
	})
	t.Run("untrusted", func(t *testing.T) {
		e := newEnv(t)
		for i := 0; i < 5; i++ {
			post(e, "203.0.113.1")
		}
		if c := post(e, "203.0.113.2"); c != 429 { // header ignored: same peer
			t.Fatalf("spoofed header bypassed limit: %d", c)
		}
	})
}
