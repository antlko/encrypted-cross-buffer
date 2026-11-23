package integration

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
)

func recvItem(t *testing.T, ch <-chan client.Event, id string) client.Event {
	t.Helper()
	timeout := time.After(15 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("event channel closed")
			}
			if ev.ID == id {
				return ev
			}
		case <-timeout:
			t.Fatalf("no event for item %s", id)
		}
	}
}

func testPNG(t *testing.T) []byte {
	rng := rand.New(rand.NewPCG(1, 2))
	img := image.NewNRGBA(image.Rect(0, 0, 400, 300))
	for y := 0; y < 300; y++ {
		for x := 0; x < 400; x++ {
			img.Set(x, y, color.NRGBA{uint8(rng.UintN(256)), uint8(rng.UintN(256)), uint8(x), 255})
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func tenKLines() []byte {
	var b strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&b, "line %05d: the quick brown fox ünïcode ✓ %d\n", i, i*7919)
	}
	return []byte(b.String())
}

func bigText(n int) []byte {
	rng := rand.New(rand.NewPCG(7, 9))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(0x20 + rng.UintN(95)) // printable ASCII: valid UTF-8, hard to compress
	}
	return b
}

type payload struct {
	name  string
	ctype uint8
	body  []byte
}

func payloads(t *testing.T) []payload {
	return []payload{
		{"text-1MiB", envelope.CTypeText, bigText(1 << 20)},
		{"text-10k-lines", envelope.CTypeText, tenKLines()},
		{"png", envelope.CTypeImagePNG, testPNG(t)},
	}
}

func roundTrip(t *testing.T, e *env, g *grp, a, b *dev, ch <-chan client.Event) {
	for _, p := range payloads(t) {
		t.Run(p.name, func(t *testing.T) {
			ctx := ctxT(t, 30*time.Second)
			ref, err := a.c.SendItem(ctx, p.ctype, p.body)
			if err != nil {
				t.Fatal(err)
			}
			ev := recvItem(t, ch, ref.ID)
			if ev.Size != ref.Size || ev.From != hexs(idBytes(a)) {
				t.Fatalf("event mismatch: %+v ref=%+v", ev, ref)
			}
			item, err := b.c.FetchItem(ctx, ev.ID)
			if err != nil {
				t.Fatal(err)
			}
			if item.CType != p.ctype || !bytes.Equal(item.Body, p.body) {
				t.Fatalf("payload differs (len %d vs %d)", len(item.Body), len(p.body))
			}
			// Replay: fetching the same item again must be rejected.
			if _, err := b.c.FetchItem(ctx, ev.ID); err == nil {
				t.Fatal("replayed fetch accepted")
			}
		})
	}
}

func idBytes(d *dev) []byte { id := d.id.DeviceID(); return id[:] }

func TestRoundTripWebSocket(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(3)
	a, b, c3 := g.devs[0], g.devs[1], g.devs[2]
	ctx, cancel := context.WithCancel(context.Background())
	chB := b.c.EventsAfter(ctx, 0)
	chC := c3.c.EventsAfter(ctx, 0)
	chA := a.c.EventsAfter(ctx, 0)
	roundTrip(t, e, g, a, b, chB)
	// Third device also got notifications (replayed ring) for the last item.
	last := func() string {
		for ev := range chC {
			if ev.Seq == 3 {
				return ev.ID
			}
		}
		return ""
	}()
	if last == "" {
		t.Fatal("device C got no events")
	}
	// A never gets notified of its own items.
	select {
	case ev := <-chA:
		t.Fatalf("sender notified of own item: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	if e.hits.count("/v1/ws") == 0 {
		t.Fatal("websocket not used")
	}
	if e.hits.count("/v1/events") != 0 {
		t.Fatal("long-poll used although websocket works")
	}
	// No goroutine leak: channels close once ctx ends.
	cancel()
	for _, ch := range []<-chan client.Event{chA, chB, chC} {
		drain(t, ch)
	}
}

func drain(t *testing.T, ch <-chan client.Event) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatal("event channel not closed after cancel")
		}
	}
}

// Live (no replay) subscription: resend until the websocket is established.
func TestLiveEvents(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := b.c.Events(ctx)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ref, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("hello live"))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case ev := <-ch:
			if ev.ID != ref.ID {
				t.Fatalf("unexpected event %+v", ev)
			}
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatal("no live event")
}

func TestRoundTripLongPollFallback(t *testing.T) {
	e := newEnv(t)
	e.hits.blockWS.Store(true) // a proxy that breaks websockets
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx, cancel := context.WithCancel(context.Background())
	chB := b.c.EventsAfter(ctx, 0)
	roundTrip(t, e, g, a, b, chB)
	if n := e.hits.count("/v1/ws"); n < 3 {
		t.Fatalf("expected >=3 websocket attempts before fallback, got %d", n)
	}
	if e.hits.count("/v1/events") == 0 {
		t.Fatal("long-poll not used")
	}
	cancel()
	drain(t, chB)
}

func Test20MBItem(t *testing.T) {
	e := newEnv(t)
	g := e.newGroup(2)
	a, b := g.devs[0], g.devs[1]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := b.c.EventsAfter(ctx, 0)
	body := bigText(20 << 20)
	ref, err := a.c.SendItem(ctx, envelope.CTypeText, body)
	if err != nil {
		t.Fatal(err)
	}
	ev := recvItem(t, ch, ref.ID)
	item, err := b.c.FetchItem(ctx, ev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(item.Body, body) {
		t.Fatal("20 MB item differs")
	}
}

// A dropped websocket is re-established and resumes with ?after=<seq>, so an
// item sent while the client was disconnected is not lost.
func TestWebSocketReconnectResumes(t *testing.T) {
	e := newEnv(t)
	px := newProxy(t, e.ts.Listener.Addr().String())
	g := e.newGroup(2, func(c *client.Config) { c.BaseURL = "http://" + px.addr })
	a, b := g.devs[0], g.devs[1]
	ctx, cancel := context.WithCancel(context.Background())
	ch := b.c.Events(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for e.hits.count("/v1/ws") < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // hello processed
	px.dropAll()
	ref, err := a.c.SendItem(ctx, envelope.CTypeText, []byte("while offline"))
	if err != nil {
		t.Fatal(err)
	}
	recvItem(t, ch, ref.ID)
	if e.hits.count("/v1/ws") < 2 {
		t.Fatal("no reconnect")
	}
	cancel()
	drain(t, ch)
}
