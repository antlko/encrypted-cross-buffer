package pairing

import (
	"context"
	"errors"
	"sync"
	"time"
)

// errGone mimics the relay's 404 for a burned/expired mailbox.
var errGone = errors.New("relay: 404 not found")

// fakeMailbox is an in-memory MailboxAPI. Tamper, if set, sees every posted
// message (to = "a"/"b", n = how many messages were already posted to that
// party, all = every message posted so far in post order) and returns what
// is actually delivered.
type fakeMailbox struct {
	mu     sync.Mutex
	q      map[string][][]byte
	count  map[string]int
	all    [][]byte
	burned bool
	burns  int
	posts  int
	wake   chan struct{}
	Tamper func(to string, n int, data []byte, all [][]byte) [][]byte
}

func newFake() *fakeMailbox {
	return &fakeMailbox{q: map[string][][]byte{}, count: map[string]int{}, wake: make(chan struct{})}
}

func (f *fakeMailbox) Post(_ context.Context, _ int, to string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.burned {
		return errGone
	}
	f.posts++
	out := [][]byte{append([]byte(nil), data...)}
	if f.Tamper != nil {
		out = f.Tamper(to, f.count[to], append([]byte(nil), data...), f.all)
	}
	f.count[to]++
	f.all = append(f.all, append([]byte(nil), data...))
	f.q[to] = append(f.q[to], out...)
	close(f.wake)
	f.wake = make(chan struct{})
	return nil
}

func (f *fakeMailbox) Get(ctx context.Context, _ int, party string, wait time.Duration) ([]byte, bool, error) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		f.mu.Lock()
		if f.burned {
			f.mu.Unlock()
			return nil, false, errGone
		}
		if len(f.q[party]) > 0 {
			d := f.q[party][0]
			f.q[party] = f.q[party][1:]
			f.mu.Unlock()
			return d, true, nil
		}
		w := f.wake
		f.mu.Unlock()
		select {
		case <-w:
		case <-t.C:
			return nil, false, nil
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (f *fakeMailbox) Burn(context.Context, int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.burned = true
	f.burns++
	close(f.wake)
	f.wake = make(chan struct{})
	return nil
}

func (f *fakeMailbox) isBurned() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.burned }
