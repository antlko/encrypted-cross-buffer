package pairing_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
	"github.com/antlko/encrypted-cross-buffer/internal/pairing"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
	"github.com/antlko/encrypted-cross-buffer/internal/roster"
)

const token = "test-enroll-token-0123456789"

type world struct {
	url  string
	gid  [16]byte
	self *keystore.Identity
	r    *roster.Roster
	cl   *client.Client
	mu   sync.Mutex
}

func newWorld(t *testing.T) *world {
	t.Helper()
	cfg := relay.Config{Addr: ":0", DataDir: t.TempDir(), EnrollToken: token, MaxItemBytes: 32 << 20,
		ItemTTL: 10 * time.Minute, Limits: relay.DefaultRateLimits()}
	srv, err := relay.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { srv.Close(); ts.Close() })
	self, _ := keystore.Generate()
	w := &world{url: ts.URL, gid: [16]byte{9, 9, 9}, self: self}
	w.r, err = roster.NewGenesis(w.gid, roster.NewEntry("a", self.Recipient(), self.PublicKey(), 1), self.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	w.cl, err = client.New(client.Config{BaseURL: ts.URL, Identity: self, GroupID: w.gid,
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return w.r, nil }), State: &keystore.State{GroupID: w.gid}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.cl.CreateGroup(context.Background(), token, w.r); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) pair(t *testing.T, joinSecretOverride string) (inviteErr, joinErr error, jid *keystore.Identity) {
	t.Helper()
	ctx := context.Background()
	id, _, err := w.cl.PairCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := pairing.NewCode(id, "")
	joinCode := code
	if joinSecretOverride != "" {
		joinCode.Secret = joinSecretOverride
	}
	jid, _ = keystore.Generate()
	inv := &pairing.Inviter{MB: w.cl.Mailbox(), Self: w.self, Roster: w.r, RelayURL: w.url,
		Publish: func(ctx context.Context, r *roster.Roster) error {
			if err := w.cl.PublishRoster(ctx, r); err != nil {
				return err
			}
			w.r = r
			return nil
		}, Timeout: 20 * time.Second}
	mb, _ := client.NewMailbox(w.url, nil)
	jn := &pairing.Joiner{MB: mb, Self: jid, Name: "b", Timeout: 20 * time.Second,
		Finish: func(ctx context.Context, j *pairing.Joined) error {
			jc, err := client.New(client.Config{BaseURL: w.url, Identity: jid, GroupID: j.GroupID,
				Roster: client.RosterFunc(func() (*roster.Roster, error) { return j.Roster, nil })})
			if err != nil {
				return err
			}
			return jc.Authenticate(ctx)
		}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, inviteErr = inv.Run(ctx, code) }()
	go func() { defer wg.Done(); _, joinErr = jn.Run(ctx, joinCode) }()
	wg.Wait()
	return
}

func TestRealRelaySuccess(t *testing.T) {
	w := newWorld(t)
	ie, je, jid := w.pair(t, "")
	if ie != nil || je != nil {
		t.Fatalf("inviter=%v joiner=%v", ie, je)
	}
	// The relay admitted the joiner: it can authenticate and fetch the roster.
	jc, _ := client.New(client.Config{BaseURL: w.url, Identity: jid, GroupID: w.gid})
	info, err := jc.FetchRoster(context.Background())
	if err != nil || info.Version != 2 || len(info.Roster.Entries) != 2 {
		t.Fatalf("fetch: %v %+v", err, info)
	}
}

func TestRealRelayWrongCode(t *testing.T) {
	w := newWorld(t)
	ie, je, jid := w.pair(t, "wrong-wrong-wrong")
	if ie == nil || je == nil {
		t.Fatalf("both must fail: %v / %v", ie, je)
	}
	info, err := w.cl.FetchRoster(context.Background())
	if err != nil || info.Version != 1 {
		t.Fatalf("roster must be unchanged: %v %+v", err, info)
	}
	jc, _ := client.New(client.Config{BaseURL: w.url, Identity: jid, GroupID: w.gid})
	if err := jc.Authenticate(context.Background()); err == nil {
		t.Fatal("joiner must not be admitted")
	}
}
