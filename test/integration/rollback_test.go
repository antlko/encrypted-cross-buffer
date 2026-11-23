package integration

import (
	"testing"
	"time"

	"github.com/antlko/encrypted-cross-buffer/internal/client"
	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
)

// A CLI roster write (ecb pair / devices rm) made while a long-running client
// holds an older in-memory State must survive that client's counter saves.
func TestClientCounterSaveNeverRollsBackRoster(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	dir := t.TempDir()
	daemonStore, err := keystore.Open(keystore.Options{Dir: dir, ForceFile: true})
	if err != nil {
		t.Fatal(err)
	}
	cliStore, _ := keystore.Open(keystore.Options{Dir: dir, ForceFile: true})
	st := &keystore.State{GroupID: g.gid, RosterBlob: []byte("roster-v2"), RosterVersion: 2}
	if err := daemonStore.SaveState(st); err != nil {
		t.Fatal(err)
	}
	cb, err := client.New(client.Config{BaseURL: e.ts.URL, Identity: b.id, GroupID: g.gid, Roster: g.box,
		State: st, Store: daemonStore, Now: e.clock.Now, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := ctxT(t, 20*time.Second)
	ref, err := a.c.SendItem(ctx, 1, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	// CLI publishes a newer roster after the daemon loaded its copy.
	if err := cliStore.UpdateState(func(s *keystore.State) error {
		s.RosterBlob, s.RosterVersion = []byte("roster-v3"), 3
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.FetchItem(ctx, ref.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.SendItem(ctx, 1, []byte("back")); err != nil {
		t.Fatal(err)
	}
	got, _ := cliStore.LoadState()
	if string(got.RosterBlob) != "roster-v3" || got.RosterVersion != 3 {
		t.Fatalf("roster rolled back to %q v%d", got.RosterBlob, got.RosterVersion)
	}
	if got.SendCounter == 0 || got.LastCounter(a.id.DeviceID()) == 0 {
		t.Fatalf("counters not persisted: %+v", got)
	}
}
