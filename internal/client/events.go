package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Event is an item notification from the relay.
type Event struct {
	T    string `json:"t"`
	ID   string `json:"id"`
	Size int64  `json:"size"`
	From string `json:"from"` // sender device id (hex)
	Seq  uint64 `json:"seq"`
}

// Sink receives events from a Transport and de-duplicates them by sequence.
type Sink struct {
	ctx  context.Context
	ch   chan<- Event
	mu   sync.Mutex
	last uint64
	has  bool
}

// After returns the highest sequence seen (or the starting point) and whether
// one is known; transports use it to resume.
func (s *Sink) After() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, s.has
}

// Advance records that the stream is current up to seq (without an event).
func (s *Sink) Advance(seq uint64) {
	s.mu.Lock()
	if !s.has || seq > s.last {
		s.last, s.has = seq, true
	}
	s.mu.Unlock()
}

// Emit delivers ev unless already seen; it blocks until the consumer takes it
// or the context ends.
func (s *Sink) Emit(ev Event) error {
	s.mu.Lock()
	if s.has && ev.Seq <= s.last {
		s.mu.Unlock()
		return nil
	}
	s.last, s.has = ev.Seq, true
	s.mu.Unlock()
	select {
	case s.ch <- ev:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// Transport delivers relay events. Run blocks until ctx ends or the
// connection fails; it calls connected once the link is established.
type Transport interface {
	Name() string
	Run(ctx context.Context, c *Client, sink *Sink, connected func()) error
}

// WebSocket is the default Transport (GET /v1/ws, client ping every PingInterval).
type WebSocket struct{}

// LongPoll is the fallback Transport (GET /v1/events?after=&wait=).
type LongPoll struct{}

func (WebSocket) Name() string { return "websocket" }
func (LongPoll) Name() string  { return "longpoll" }

// Events returns a channel of item notifications for items sent by OTHER
// devices, starting from "now". It reconnects with jittered exponential
// backoff (BackoffMin..BackoffMax) and falls back to long-polling after
// WSFailuresBeforePoll consecutive WebSocket connection failures (retrying the
// WebSocket every WSRetryAfter). The channel is closed when ctx ends.
func (c *Client) Events(ctx context.Context) <-chan Event {
	return c.events(ctx, 0, false)
}

// EventsAfter is Events but first replays relay-buffered events with seq > after.
func (c *Client) EventsAfter(ctx context.Context, after uint64) <-chan Event {
	return c.events(ctx, after, true)
}

func (c *Client) events(ctx context.Context, after uint64, has bool) <-chan Event {
	out := make(chan Event, 16)
	sink := &Sink{ctx: ctx, ch: out, last: after, has: has}
	go func() {
		defer close(out)
		c.eventLoop(ctx, sink)
	}()
	return out
}

func (c *Client) eventLoop(ctx context.Context, sink *Sink) {
	var primary Transport = WebSocket{}
	var fallback Transport = LongPoll{}
	if c.cfg.Transport != nil {
		primary, fallback = c.cfg.Transport, nil
	}
	fails := 0
	backoff := c.cfg.BackoffMin
	for ctx.Err() == nil {
		tr, runCtx, cancel := primary, ctx, context.CancelFunc(func() {})
		if fallback != nil && fails >= c.cfg.WSFailuresBeforePoll {
			c.log.Warn("websocket unavailable, using long-poll", "failures", fails)
			tr = fallback
			runCtx, cancel = context.WithTimeout(ctx, c.cfg.WSRetryAfter)
		}
		connected := false
		err := tr.Run(runCtx, c, sink, func() { connected = true })
		cancel()
		if ctx.Err() != nil {
			return
		}
		if tr == fallback && runCtx.Err() != nil {
			// Time to retry the websocket.
			fails, backoff = 0, c.cfg.BackoffMin
			continue
		}
		if connected {
			backoff = c.cfg.BackoffMin
			if tr == primary {
				fails = 0
			}
		} else if tr == primary {
			fails++
		}
		c.log.Debug("event transport ended", "transport", tr.Name(), "connected", connected, "err_kind", fmt.Sprintf("%T", err))
		if fallback != nil && fails >= c.cfg.WSFailuresBeforePoll && tr == primary {
			continue // switch immediately
		}
		// Equal jitter: backoff/2 .. backoff.
		d := backoff/2 + time.Duration(rand.Int64N(int64(backoff/2)+1))
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return
		}
		backoff = min(backoff*2, c.cfg.BackoffMax)
	}
}

// ---- websocket -----------------------------------------------------------

func (WebSocket) Run(ctx context.Context, c *Client, sink *Sink, connected func()) error {
	tok, err := c.ensureToken(ctx, "")
	if err != nil {
		return err
	}
	u := *c.base
	u.Path = "/v1/ws"
	if after, ok := sink.After(); ok {
		u.RawQuery = "after=" + strconv.FormatUint(after, 10)
	}
	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient: c.hc,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			c.invalidate(tok)
		}
		return err
	}
	conn.SetReadLimit(64 << 10)
	connected()
	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // keepalive
		defer wg.Done()
		t := time.NewTicker(c.cfg.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(cctx, 10*time.Second)
				err := conn.Ping(pctx)
				pc()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		_ = conn.Close(websocket.StatusNormalClosure, "")
		wg.Wait()
	}()
	for {
		typ, data, err := conn.Read(cctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			continue
		}
		var ev Event
		if json.Unmarshal(data, &ev) != nil {
			continue
		}
		if ev.T == "hello" {
			sink.Advance(ev.Seq)
			continue
		}
		if ev.T != "item" {
			continue
		}
		if err := sink.Emit(ev); err != nil {
			return err
		}
	}
}

// ---- long-poll -----------------------------------------------------------

func (LongPoll) Run(ctx context.Context, c *Client, sink *Sink, connected func()) error {
	wait := c.cfg.PollWait
	for {
		q := url.Values{"wait": {strconv.Itoa(int(wait / time.Second))}}
		if after, ok := sink.After(); ok {
			q.Set("after", strconv.FormatUint(after, 10))
		}
		rctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
		resp, err := c.send(rctx, "GET", "/v1/events?"+q.Encode(), nil, nil, true)
		if err != nil {
			cancel()
			return err
		}
		if resp.StatusCode != http.StatusOK {
			cancel()
			return apiError(resp)
		}
		var out struct {
			Events []Event `json:"events"`
			Seq    uint64  `json:"seq"`
		}
		err = decodeJSON(resp.Body, &out)
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			return err
		}
		connected()
		for _, ev := range out.Events {
			if err := sink.Emit(ev); err != nil {
				return err
			}
		}
		sink.Advance(out.Seq)
		if wait == 0 {
			select { // avoid a hot loop if misconfigured
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
