package relay

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a map of token buckets keyed by IP or device.
type limiter struct {
	mu   sync.Mutex
	m    map[string]*bucket
	rate Rate
	now  func() time.Time
}

func newLimiter(r Rate, now func() time.Time) *limiter {
	if r.Burst <= 0 {
		r.Burst = 1
	}
	if r.Every <= 0 {
		r.Every = time.Second
	}
	return &limiter{m: map[string]*bucket{}, rate: r, now: now}
}

// refill returns the bucket for key with tokens topped up. Caller holds mu.
func (l *limiter) refill(key string) *bucket {
	t := l.now()
	b := l.m[key]
	if b == nil {
		b = &bucket{tokens: float64(l.rate.Burst), last: t}
		l.m[key] = b
		return b
	}
	if el := t.Sub(b.last); el > 0 {
		b.tokens += float64(el) / float64(l.rate.Every)
		if b.tokens > float64(l.rate.Burst) {
			b.tokens = float64(l.rate.Burst)
		}
		b.last = t
	}
	return b
}

// allow consumes one token; false when the bucket is empty.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// peek reports whether a token is available without consuming it.
func (l *limiter) peek(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refill(key).tokens >= 1
}

// take consumes one token if available (used after a failed attempt).
func (l *limiter) take(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.refill(key); b.tokens >= 1 {
		b.tokens--
	}
}

// sweep drops buckets that are full again (idle).
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.m {
		if b := l.refill(k); b.tokens >= float64(l.rate.Burst) {
			delete(l.m, k)
		}
	}
}
