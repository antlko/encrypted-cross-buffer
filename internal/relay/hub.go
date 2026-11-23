package relay

import (
	"context"
	"sync"
)

const ringSize = 64

// Event is an item notification (also the long-poll payload).
type Event struct {
	T    string `json:"t"`
	ID   string `json:"id"`
	Size int64  `json:"size"`
	From string `json:"from"`
	Seq  uint64 `json:"seq"`
}

type ghub struct {
	seq     uint64
	ring    []Event
	waiters map[chan struct{}]struct{}
}

type tracked struct {
	gid    string
	pub    pubKey
	cancel context.CancelCauseFunc
}

// hub holds per-group event rings, waiters and open connections (for revocation).
type hub struct {
	mu     sync.Mutex
	groups map[string]*ghub
	conns  map[*tracked]struct{}
}

func newHub() *hub {
	return &hub{groups: map[string]*ghub{}, conns: map[*tracked]struct{}{}}
}

func (h *hub) g(gid string) *ghub {
	g := h.groups[gid]
	if g == nil {
		g = &ghub{waiters: map[chan struct{}]struct{}{}}
		h.groups[gid] = g
	}
	return g
}

func (h *hub) publish(gid string, ev Event) Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	g := h.g(gid)
	g.seq++
	ev.Seq = g.seq
	g.ring = append(g.ring, ev)
	if len(g.ring) > ringSize {
		g.ring = append([]Event(nil), g.ring[len(g.ring)-ringSize:]...)
	}
	for ch := range g.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return ev
}

// since returns ring events with seq > after not sent by exclude, plus the
// group's current seq. If after is ahead of the current seq (relay restarted),
// the whole ring is returned.
func (h *hub) since(gid string, after uint64, exclude string) ([]Event, uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	g := h.g(gid)
	if after > g.seq {
		after = 0
	}
	var out []Event
	for _, e := range g.ring {
		if e.Seq > after && e.From != exclude {
			out = append(out, e)
		}
	}
	return out, g.seq
}

func (h *hub) cur(gid string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.g(gid).seq
}

// subscribe returns a wake channel (cap 1) and its cancel func.
func (h *hub) subscribe(gid string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.g(gid).waiters[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.g(gid).waiters, ch)
		h.mu.Unlock()
	}
}

// track registers a connection so a roster change can cancel it.
func (h *hub) track(gid string, pub pubKey, cancel context.CancelCauseFunc) func() {
	t := &tracked{gid: gid, pub: pub, cancel: cancel}
	h.mu.Lock()
	h.conns[t] = struct{}{}
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.conns, t)
		h.mu.Unlock()
	}
}

// kick cancels connections of gid whose key is not in keep.
func (h *hub) kick(gid string, keep map[pubKey]struct{}) {
	h.mu.Lock()
	var victims []*tracked
	for t := range h.conns {
		if t.gid != gid {
			continue
		}
		if _, ok := keep[t.pub]; !ok {
			victims = append(victims, t)
		}
	}
	h.mu.Unlock()
	for _, t := range victims {
		t.cancel(errRevoked)
	}
}
