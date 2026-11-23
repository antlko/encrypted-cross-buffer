package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

func TestRosterRemovalIsImmediate(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(3)
	a, b, c3 := g.devs[0], g.devs[1], g.devs[2]
	ctx := ctxT(t, 30*time.Second)
	held, _ := g.box.Roster() // version 3, what B still holds

	bTok := e.rawToken(b.id, g.gid)
	ws, _, err := websocket.Dial(ctx, e.ts.URL+"/v1/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + bTok}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	var wg sync.WaitGroup
	wsErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				wsErr <- err
				return
			}
		}
	}()
	pollCode := make(chan int, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		code, _ := e.rawJSON("GET", "/v1/events?wait=25", bTok, nil, nil)
		pollCode <- code
	}()
	time.Sleep(200 * time.Millisecond) // let both park on the relay

	// A publishes v4 without B.
	r4, err := held.Remove(b.id.DeviceID())
	if err != nil {
		t.Fatal(err)
	}
	if err := r4.Sign(a.id.Ed25519); err != nil {
		t.Fatal(err)
	}
	if err := a.c.PublishRoster(ctx, r4); err != nil {
		t.Fatal(err)
	}
	g.box.set(r4)

	select {
	case err := <-wsErr:
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
			t.Fatalf("ws closed with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("removed device's websocket still open")
	}
	select {
	case code := <-pollCode:
		if code != 401 {
			t.Fatalf("long-poll of removed device: %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("removed device's long-poll still parked")
	}
	wg.Wait()

	// Its token is dead immediately; it cannot re-authenticate.
	if code, _ := e.rawJSON("GET", "/v1/events", bTok, nil, nil); code != 401 {
		t.Fatalf("old token still valid: %d", code)
	}
	if code, _ := e.rawAuth(b.id, g.gid, nil); code != 401 {
		t.Fatalf("removed device re-authenticated: %d", code)
	}
	if _, err := b.c.SendItem(ctx, envelope.CTypeText, []byte("x")); !client.IsStatus(err, 401) {
		t.Fatalf("removed device send: %v", err)
	}
	if _, err := b.c.FetchRoster(ctx); !client.IsStatus(err, 401) {
		t.Fatalf("removed device roster fetch: %v", err)
	}

	// A new item is for C only: B cannot decrypt it even with the bytes.
	ref, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("after removal"))
	if err != nil {
		t.Fatal(err)
	}
	if item, err := c3.c.FetchItem(ctx, ref.ID); err != nil || string(item.Body) != "after removal" {
		t.Fatalf("remaining member fetch: %v", err)
	}
	cTok := e.rawToken(c3.id, g.gid)
	code, raw := e.rawGet("/v1/items/"+ref.ID, cTok)
	if code != 200 {
		t.Fatal(code)
	}
	_, err = envelope.OpenBytes(raw, envelope.OpenParams{
		GroupID: g.gid, Lookup: held.KeyLookup(), Identity: b.id.X25519,
		LastCounter: func([16]byte) uint64 { return 0 }, Now: e.clock.Now})
	if err == nil || !errors.Is(err, envelope.ErrDecrypt) {
		t.Fatalf("removed device could open new item: %v", err)
	}

	// Relay rules: same version again, non-member signer, bad signature.
	if err := a.c.PublishRoster(ctx, r4); !client.IsStatus(err, 409) {
		t.Fatalf("stale version: %v", err)
	}
	aTok := e.rawToken(a.id, g.gid)
	blob, _ := r4.Seal()
	gh := hexs(g.gid[:])
	post := func(signer *keystore.Identity, version uint64, mutate func([]byte)) int {
		keys := []ed25519.PublicKey{a.id.PublicKey()}
		sig := ed25519.Sign(signer.Ed25519, relay.RosterPubMessage(g.gid, version, blob, keys))
		mutate(sig)
		code, _ := e.rawJSON("POST", "/v1/groups/"+gh+"/roster", aTok, map[string]any{
			"version": version, "blob": blob, "keys": [][]byte{a.id.PublicKey()}, "sig": sig,
			"signer": []byte(signer.PublicKey())}, nil)
		return code
	}
	if code := post(b.id, 5, func([]byte) {}); code != 403 { // B is no longer a member
		t.Fatalf("removed signer: %d", code)
	}
	if code := post(a.id, 5, func(s []byte) { s[3] ^= 1 }); code != 403 {
		t.Fatalf("bad roster sig: %d", code)
	}
	if code := post(a.id, 4, func([]byte) {}); code != 409 {
		t.Fatalf("old version: %d", code)
	}
	// Fetch returns what was published.
	info, err := a.c.FetchRoster(ctx)
	if err != nil || info.Version != 4 {
		t.Fatalf("fetch roster: %v %+v", err, info)
	}
	if err := info.Roster.Verify(held); err != nil {
		t.Fatalf("published roster does not verify: %v", err)
	}
	// Cross-group access is refused uniformly.
	other := [16]byte{0xab}
	if code, _ := e.rawGet("/v1/groups/"+hexs(other[:])+"/roster", aTok); code != 403 {
		t.Fatalf("foreign group roster: %d", code)
	}
}

func (e *env) rawGet(path, tok string) (int, []byte) {
	return e.rawJSON("GET", path, tok, nil, nil)
}

func TestRestartKeepsGroups(t *testing.T) {
	dir := t.TempDir()
	e1 := startEnv(t, dir)
	g := e1.newGroup(2)
	a := g.devs[0]
	r, _ := g.box.Roster()
	wantBlob, _ := e1.fetchBlob(a)
	e1.stop()

	e2 := startEnv(t, dir)
	a2 := e2.attach("A", a.id, g.gid, g.box)
	ctx := ctxT(t, 20*time.Second)
	if err := a2.c.Authenticate(ctx); err != nil {
		t.Fatalf("auth after restart: %v", err)
	}
	info, err := a2.c.FetchRoster(ctx)
	if err != nil || info.Version != r.Version || !bytes.Equal(info.Blob, wantBlob) {
		t.Fatalf("roster after restart: %v", err)
	}
	// Both devices are still allowed; an outsider is not.
	b2 := e2.attach("B", g.devs[1].id, g.gid, g.box)
	if err := b2.c.Authenticate(ctx); err != nil {
		t.Fatalf("B after restart: %v", err)
	}
	out, _ := keystore.Generate()
	if code, _ := e2.rawAuth(out, g.gid, nil); code != 401 {
		t.Fatalf("outsider: %d", code)
	}
	fi, err := os.Stat(filepath.Join(dir, "groups.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("groups.json: %v %v", err, fi)
	}
	// Items are short-lived and not kept across restarts, but sending works.
	if _, err := a2.c.SendItem(ctx, envelope.CTypeText, []byte("post-restart")); err != nil {
		t.Fatal(err)
	}
}

func (e *env) fetchBlob(d *dev) ([]byte, error) {
	info, err := d.c.FetchRoster(ctxT(e.t, 10*time.Second))
	if err != nil {
		return nil, err
	}
	return info.Blob, nil
}

// A persisted roster of an older run must not be replaceable by a lower version.
func TestPublishNeedsCurrentMember(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	a := g.devs[0]
	// A device that is not in the group cannot even authenticate, so it cannot publish.
	x := e.newDev("X", g.gid, g.box)
	r, _ := g.box.Roster()
	r2, _ := r.Add(a.id.DeviceID(), roster.NewEntry("X", x.id.Recipient(), x.id.PublicKey(), 1))
	_ = r2.Sign(a.id.Ed25519)
	if err := x.c.PublishRoster(context.Background(), r2); !client.IsStatus(err, 401) {
		t.Fatalf("outsider publish: %v", err)
	}
}
