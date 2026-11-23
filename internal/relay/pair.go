package relay

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	pairTTL         = 5 * time.Minute
	pairMaxMsgs     = 8
	pairMaxPerGroup = 4
	pairMaxData     = 16 << 10
	pairMaxID       = 99
)

type mailbox struct {
	id      int
	gid     string
	exp     time.Time
	q       map[string][][]byte // "a" / "b" -> pending messages
	total   int
	changed chan struct{} // closed on any change; replaced after
}

type pairMgr struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[int]*mailbox
}

func newPairMgr(now func() time.Time) *pairMgr {
	return &pairMgr{now: now, m: map[int]*mailbox{}}
}

type pairErr int

const (
	pairOK pairErr = iota
	pairTooMany
	pairNoSlot
	pairGone
	pairFull
)

func (p *pairMgr) create(gid string) (int, pairErr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
	n := 0
	for _, mb := range p.m {
		if mb.gid == gid {
			n++
		}
	}
	if n >= pairMaxPerGroup {
		return 0, pairTooMany
	}
	var free []int
	for i := 1; i <= pairMaxID; i++ {
		if p.m[i] == nil {
			free = append(free, i)
		}
	}
	if len(free) == 0 {
		return 0, pairNoSlot
	}
	id := free[rand.IntN(len(free))]
	p.m[id] = &mailbox{id: id, gid: gid, exp: p.now().Add(pairTTL), q: map[string][][]byte{}, changed: make(chan struct{})}
	return id, pairOK
}

// live returns the mailbox if it exists and has not expired. Caller holds mu.
func (p *pairMgr) live(id int) *mailbox {
	mb := p.m[id]
	if mb == nil {
		return nil
	}
	if !p.now().Before(mb.exp) {
		p.burnLocked(id)
		return nil
	}
	return mb
}

func (p *pairMgr) burnLocked(id int) {
	if mb := p.m[id]; mb != nil {
		delete(p.m, id)
		close(mb.changed)
	}
}

func (p *pairMgr) burn(id int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.burnLocked(id)
}

func (p *pairMgr) post(id int, to string, data []byte) pairErr {
	p.mu.Lock()
	defer p.mu.Unlock()
	mb := p.live(id)
	if mb == nil {
		return pairGone
	}
	if mb.total >= pairMaxMsgs {
		return pairFull
	}
	mb.total++
	mb.q[to] = append(mb.q[to], data)
	close(mb.changed)
	mb.changed = make(chan struct{})
	return pairOK
}

// get pops the next message for party `for`, waiting up to wait. ok=false with
// gone=false means timeout.
func (p *pairMgr) get(ctx context.Context, id int, party string, wait time.Duration) (data []byte, gone bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		p.mu.Lock()
		mb := p.live(id)
		if mb == nil {
			p.mu.Unlock()
			return nil, true
		}
		if q := mb.q[party]; len(q) > 0 {
			d := q[0]
			mb.q[party] = q[1:]
			// Count limit reached and everything delivered: auto-burn.
			if mb.total >= pairMaxMsgs && len(mb.q["a"])+len(mb.q["b"]) == 0 {
				p.burnLocked(id)
			}
			p.mu.Unlock()
			return d, false
		}
		ch := mb.changed
		p.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

func (p *pairMgr) sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepLocked()
}

func (p *pairMgr) sweepLocked() {
	for id := range p.m {
		p.live(id)
	}
}
