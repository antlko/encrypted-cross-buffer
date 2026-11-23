package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/envelope"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
)

func TestMailboxFlowAndBurn(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	a := g.devs[0]
	ctx := ctxT(t, 30*time.Second)
	if code, _ := e.rawJSON("POST", "/v1/pair", "", nil, nil); code != 401 {
		t.Fatalf("unauthenticated mailbox create: %d", code)
	}
	id, ttl, err := a.c.PairCreate(ctx)
	if err != nil || id < 1 || id > 99 || ttl != 5*time.Minute {
		t.Fatalf("create: %d %v %v", id, ttl, err)
	}
	joiner, err := client.NewMailbox(e.ts.URL, nil) // no credentials
	if err != nil {
		t.Fatal(err)
	}
	mine := a.c.Mailbox()

	// Long-poll: the joiner waits, then A posts.
	got := make(chan []byte, 1)
	go func() {
		d, ok, err := joiner.Get(ctx, id, "b", 5*time.Second)
		if err != nil || !ok {
			got <- nil
			return
		}
		got <- d
	}()
	time.Sleep(100 * time.Millisecond)
	if err := mine.Post(ctx, id, "b", []byte("pake-msg-1")); err != nil {
		t.Fatal(err)
	}
	if d := <-got; string(d) != "pake-msg-1" {
		t.Fatalf("got %q", d)
	}
	// Reverse direction, and messages are addressed.
	if err := joiner.Post(ctx, id, "a", []byte("pake-msg-2")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := joiner.Get(ctx, id, "b", 0); ok {
		t.Fatal("b received a message addressed to a")
	}
	d, ok, err := mine.Get(ctx, id, "a", 0)
	if err != nil || !ok || string(d) != "pake-msg-2" {
		t.Fatalf("a got %q %v %v", d, ok, err)
	}
	// Empty: timeout, not error.
	if _, ok, err := mine.Get(ctx, id, "a", 0); ok || err != nil {
		t.Fatalf("empty get: %v %v", ok, err)
	}
	// Validation.
	if err := joiner.Post(ctx, id, "c", []byte("x")); !client.IsStatus(err, 400) {
		t.Fatalf("bad party: %v", err)
	}
	if err := joiner.Post(ctx, id, "a", bytes.Repeat([]byte("z"), 16<<10+1)); !client.IsStatus(err, 400) {
		t.Fatalf("oversize msg: %v", err)
	}
	if err := joiner.Post(ctx, id, "a", bytes.Repeat([]byte("z"), 16<<10)); err != nil {
		t.Fatalf("16 KiB msg: %v", err)
	}
	// Burn (anyone, idempotent) kills it for everybody.
	if err := joiner.Burn(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := joiner.Burn(ctx, id); err != nil {
		t.Fatalf("second burn: %v", err)
	}
	if err := mine.Post(ctx, id, "b", []byte("x")); !client.IsStatus(err, 404) {
		t.Fatalf("post after burn: %v", err)
	}
	if _, _, err := mine.Get(ctx, id, "a", 0); !client.IsStatus(err, 404) {
		t.Fatalf("get after burn: %v", err)
	}
}

func TestMailboxBurnWakesWaiter(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	ctx := ctxT(t, 30*time.Second)
	id, _, _ := g.devs[0].c.PairCreate(ctx)
	m := g.devs[0].c.Mailbox()
	res := make(chan error, 1)
	go func() { _, _, err := m.Get(ctx, id, "a", 20*time.Second); res <- err }()
	time.Sleep(100 * time.Millisecond)
	_ = m.Burn(ctx, id)
	select {
	case err := <-res:
		if !client.IsStatus(err, 404) {
			t.Fatalf("waiter: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter not woken by burn")
	}
}

func TestMailboxMaxMessagesAndLimits(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	ctx := ctxT(t, 30*time.Second)
	c := g.devs[0].c
	m := c.Mailbox()

	// Count limit: 8 accepted, the 9th fails and burns the mailbox.
	id, _, _ := c.PairCreate(ctx)
	for i := 0; i < 8; i++ {
		if err := m.Post(ctx, id, "a", []byte{byte(i + 1)}); err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
	}
	if err := m.Post(ctx, id, "a", []byte("9")); !client.IsStatus(err, 429) {
		t.Fatalf("9th message: %v", err)
	}
	if _, _, err := m.Get(ctx, id, "a", 0); !client.IsStatus(err, 404) {
		t.Fatalf("mailbox not burned: %v", err)
	}
	// Auto-burn once the 8th message has been delivered.
	id, _, _ = c.PairCreate(ctx)
	for i := 0; i < 8; i++ {
		_ = m.Post(ctx, id, "b", []byte{byte(i + 1)})
	}
	for i := 0; i < 8; i++ {
		d, ok, err := m.Get(ctx, id, "b", 0)
		if err != nil || !ok || d[0] != byte(i+1) {
			t.Fatalf("read %d: %v %v %v", i, d, ok, err)
		}
	}
	if err := m.Post(ctx, id, "b", []byte("late")); !client.IsStatus(err, 404) {
		t.Fatalf("not auto-burned: %v", err)
	}
	_ = m.Burn(ctx, id)

	// Max 4 active per group.
	var ids []int
	for i := 0; i < 4; i++ {
		id, _, err := c.PairCreate(ctx)
		if err != nil {
			t.Fatalf("mailbox %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	if _, _, err := c.PairCreate(ctx); !client.IsStatus(err, 429) {
		t.Fatalf("5th mailbox: %v", err)
	}
	_ = m.Burn(ctx, ids[0])
	if _, _, err := c.PairCreate(ctx); err != nil {
		t.Fatalf("after burn: %v", err)
	}
}

func TestMailboxTTL(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(1)
	ctx := ctxT(t, 30*time.Second)
	m := g.devs[0].c.Mailbox()
	id, _, _ := g.devs[0].c.PairCreate(ctx)
	if err := m.Post(ctx, id, "b", []byte("hi")); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(4*time.Minute + 50*time.Second)
	if _, ok, err := m.Get(ctx, id, "b", 0); err != nil || !ok {
		t.Fatalf("before TTL: %v %v", ok, err)
	}
	_ = m.Post(ctx, id, "b", []byte("again"))
	e.clock.Advance(11 * time.Second)
	if _, _, err := m.Get(ctx, id, "b", 0); !client.IsStatus(err, 404) {
		t.Fatalf("after TTL: %v", err)
	}
	e.srv.Sweep() // sweeper path must not panic and frees the slot
}

func TestMailboxPerIPRateLimit(t *testing.T) {
	e := newEnv(t, func(c *relay.Config) {
		c.Limits = relay.DefaultRateLimits()
		c.Limits.Pair = relay.Rate{Burst: 5, Every: time.Hour}
	})
	g := e.newGroup(1)
	ctx := ctxT(t, 30*time.Second)
	id, _, _ := g.devs[0].c.PairCreate(ctx)
	m, _ := client.NewMailbox(e.ts.URL, nil)
	var limited bool
	for i := 0; i < 10; i++ {
		_, _, err := m.Get(ctx, id, "a", 0)
		if client.IsStatus(err, 429) {
			limited = true
			if i < 5 {
				t.Fatalf("limited too early (%d)", i)
			}
			break
		}
	}
	if !limited {
		t.Fatal("per-IP limit never kicked in")
	}
	if err := m.Burn(ctx, id); !client.IsStatus(err, 429) {
		t.Fatalf("burn is limited too: %v", err)
	}
}

// ---- logging -------------------------------------------------------------

func TestNoSecretsInLogs(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const marker = "TOP-SECRET-CLIPBOARD-MARKER-31337"
	const pairMarker = "PAIR-MESSAGE-MARKER-8472"

	tok := e.rawToken(a.id, g.gid)
	ch := b.c.EventsAfter(ctx, 0)
	ref, err := a.c.SendItem(ctx, envelope.CTypeText, []byte(marker))
	if err != nil {
		t.Fatal(err)
	}
	recvItem(t, ch, ref.ID)
	if _, err := b.c.FetchItem(ctx, ref.ID); err != nil {
		t.Fatal(err)
	}
	id, _, _ := a.c.PairCreate(ctx)
	_ = a.c.Mailbox().Post(ctx, id, "b", []byte(pairMarker))
	e.rawJSON("POST", "/v1/groups", "", map[string]any{}, map[string]string{"X-ECB-Enroll": "wrong-enroll-secret-xyz"})
	e.rawJSON("GET", "/v1/events?token=query-token-secret", "query-token-secret", nil, nil)
	cancel()
	drain(t, ch)
	e.stop()

	logs := e.logs.String()
	if !strings.Contains(logs, "rid=") || !strings.Contains(logs, "status=") {
		t.Fatalf("expected request logs, got:\n%s", logs)
	}
	secrets := map[string]string{
		"enroll token":   enrollToken,
		"wrong enroll":   "wrong-enroll-secret-xyz",
		"bearer token":   tok,
		"query token":    "query-token-secret",
		"item body":      marker,
		"pair message":   pairMarker,
		"age secret key": a.id.X25519.String(),
		"ed25519 seed":   hexs(a.id.Ed25519.Seed()),
		"ed25519 seed b": string(b64e(a.id.Ed25519.Seed())),
		"bearer header":  "Bearer ",
		"authorization":  "Authorization",
		"peer ip":        "127.0.0.1",
	}
	for name, s := range secrets {
		if strings.Contains(logs, s) {
			t.Errorf("log output contains %s", name)
		}
	}
}
