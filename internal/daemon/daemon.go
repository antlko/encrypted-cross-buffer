// Package daemon is the clipboard sync loop: it watches the local clipboard
// and sends changes to the other devices through the relay, and applies items
// received from them. Logs never contain clipboard content or key material.
package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/clip"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

// ErrRevoked is returned by Run when the relay permanently refuses this
// device (it was removed from the group).
var ErrRevoked = errors.New("this device has been removed from the group: the relay no longer accepts its key")

// Options configure a Daemon. Zero timing fields take the production defaults.
type Options struct {
	Store    *keystore.Store
	Identity *keystore.Identity
	Clip     clip.Clipboard
	Logger   *slog.Logger

	Debounce      time.Duration // default 300 ms
	ConfigPoll    time.Duration // default 2 s
	RosterRefresh time.Duration // default 5 min
	// EchoWindow: after applying a remote item, local events of the same kind
	// are ignored for this long (the OS may hand back re-encoded content whose
	// hash differs). Default 1.5 s; negative disables.
	EchoWindow time.Duration
	// ClientTune adjusts the relay client configuration (tests).
	ClientTune func(*client.Config)
}

// Daemon is the sync loop.
type Daemon struct {
	o      Options
	log    *slog.Logger
	state  *keystore.State
	self   [16]byte
	cl     *client.Client
	cancel context.CancelCauseFunc

	rosMu sync.RWMutex
	ros   *roster.Roster

	cfg                 Config
	cfgStamp            fileStamp
	lastRefr            time.Time
	lastSent            [32]byte
	lastApplied         [32]byte
	hasSent, hasApplied bool
	appliedAt           map[clip.Kind]time.Time
	seen                map[string]struct{}
	seenOrder           []string

	ready     chan struct{}
	readyOnce sync.Once
	sent      atomic.Int64
	applied   atomic.Int64
}

type fileStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

// New loads the state and roster and prepares a Daemon.
func New(o Options) (*Daemon, error) {
	if o.Store == nil || o.Identity == nil || o.Clip == nil {
		return nil, errors.New("daemon: Store, Identity and Clip are required")
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Debounce <= 0 {
		o.Debounce = 300 * time.Millisecond
	}
	if o.ConfigPoll <= 0 {
		o.ConfigPoll = 2 * time.Second
	}
	if o.RosterRefresh <= 0 {
		o.RosterRefresh = 5 * time.Minute
	}
	if o.EchoWindow == 0 {
		o.EchoWindow = 1500 * time.Millisecond
	}
	st, err := o.Store.LoadState()
	if err != nil {
		return nil, err
	}
	if st.RelayURL == "" || len(st.RosterBlob) == 0 {
		return nil, errors.New("this device is not set up yet: run `ecb init` or `ecb join` first")
	}
	r, err := roster.Open(st.RosterBlob, o.Identity.X25519)
	if err != nil {
		return nil, errors.New("cannot read the stored roster with this device's key (wrong keystore?)")
	}
	d := &Daemon{o: o, log: o.Logger, state: st, self: o.Identity.DeviceID(), ros: r,
		appliedAt: map[clip.Kind]time.Time{}, seen: map[string]struct{}{}, ready: make(chan struct{})}
	if _, ok := r.Lookup(d.self); !ok {
		return nil, ErrRevoked
	}
	d.cfg, err = LoadConfig(o.Store.Dir())
	if err != nil {
		d.log.Warn("config unreadable, using defaults", "err", err)
	}
	d.cfgStamp = stampOf(o.Store.Dir())
	ccfg := client.Config{
		BaseURL: st.RelayURL, Identity: o.Identity, GroupID: st.GroupID,
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return d.roster(), nil }),
		State:  st, Store: o.Store, Logger: o.Logger,
		Transport: &transport{d: d},
	}
	if o.ClientTune != nil {
		o.ClientTune(&ccfg)
	}
	d.cl, err = client.New(ccfg)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Ready is closed once the event stream is connected.
func (d *Daemon) Ready() <-chan struct{} { return d.ready }

// Sent and Applied count items sent / applied (tests, status).
func (d *Daemon) Sent() int64    { return d.sent.Load() }
func (d *Daemon) Applied() int64 { return d.applied.Load() }

// Roster returns the currently held roster.
func (d *Daemon) Roster() *roster.Roster { return d.roster() }

func (d *Daemon) roster() *roster.Roster {
	d.rosMu.RLock()
	defer d.rosMu.RUnlock()
	return d.ros
}

func stampOf(dir string) fileStamp {
	fi, err := os.Stat(filepath.Join(dir, ConfigFile))
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{fi.ModTime(), fi.Size(), true}
}

func hashOf(k clip.Kind, b []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{byte(k)})
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (d *Daemon) revoke() { d.cancel(ErrRevoked) }

func isAuthErr(err error) bool { return client.IsStatus(err, 401) || client.IsStatus(err, 403) }

// checkRevoked re-authenticates; two consecutive 401/403 mean the relay
// permanently refuses this device.
func (d *Daemon) checkRevoked(ctx context.Context) bool {
	for i := 0; i < 2; i++ {
		err := d.cl.Authenticate(ctx)
		if err == nil || !isAuthErr(err) {
			return false
		}
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
			return false
		}
	}
	d.revoke()
	return true
}

func (d *Daemon) onErr(ctx context.Context, err error) {
	if isAuthErr(err) {
		d.checkRevoked(ctx)
	}
}

// transport wraps the default websocket/long-poll transports to (a) signal
// readiness and (b) detect revocation, which the event loop would otherwise
// retry silently forever.
type transport struct {
	d     *Daemon
	ws    client.WebSocket
	lp    client.LongPoll
	fails int
}

func (t *transport) Name() string { return "ecb" }

func (t *transport) Run(ctx context.Context, c *client.Client, sink *client.Sink, connected func()) error {
	conn := false
	cb := func() {
		conn = true
		t.d.readyOnce.Do(func() { close(t.d.ready) })
		connected()
	}
	var err error
	if t.fails >= 3 {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		t.d.log.Warn("websocket unavailable, using long-poll")
		err = t.lp.Run(rctx, c, sink, cb)
		cancel()
		t.fails = 0
	} else {
		err = t.ws.Run(ctx, c, sink, cb)
		if conn {
			t.fails = 0
		} else {
			t.fails++
		}
	}
	if ctx.Err() == nil {
		t.d.checkRevoked(ctx)
	}
	return err
}

// Run syncs until ctx ends (returns nil) or the device is revoked (ErrRevoked).
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	d.cancel = cancel
	defer cancel(nil)

	if err := d.cl.Authenticate(ctx); err != nil {
		if isAuthErr(err) {
			return ErrRevoked
		}
		d.log.Warn("relay not reachable yet; will keep retrying", "err_kind", errKind(err))
	}
	d.refreshRoster(ctx, "startup")

	events := d.cl.Events(ctx)
	local := d.o.Clip.Watch(ctx)
	d.log.Info("daemon started", "mode", d.cfg.Mode, "devices", len(d.roster().Entries))

	cfgT := time.NewTicker(d.o.ConfigPoll)
	defer cfgT.Stop()
	rosT := time.NewTicker(d.o.RosterRefresh)
	defer rosT.Stop()

	var pending *clip.Event
	var tm *time.Timer
	var tmC <-chan time.Time
	defer func() {
		if tm != nil {
			tm.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if errors.Is(context.Cause(ctx), ErrRevoked) {
				d.log.Error(ErrRevoked.Error())
				return ErrRevoked
			}
			d.log.Info("daemon stopped")
			return nil
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			d.handleRemote(ctx, ev)
		case e, ok := <-local:
			if !ok {
				local = nil
				continue
			}
			if e.Sensitive {
				// Never sync, and never send an older pending item either: it
				// is no longer what is on the clipboard.
				pending = nil
				tmC = nil
				d.log.Info("sensitive clipboard item skipped (password manager)", "kind", e.Kind.String())
				continue
			}
			pending = &e
			if tm == nil {
				tm = time.NewTimer(d.o.Debounce)
			} else {
				if !tm.Stop() {
					select {
					case <-tm.C:
					default:
					}
				}
				tm.Reset(d.o.Debounce)
			}
			tmC = tm.C
		case <-tmC:
			tmC = nil
			if pending != nil {
				e := *pending
				pending = nil
				d.handleLocal(ctx, e)
			}
		case <-cfgT.C:
			d.reloadConfig()
		case <-rosT.C:
			d.refreshRoster(ctx, "periodic")
		}
	}
}

func errKind(err error) string {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return "http_" + strconv.Itoa(ae.Status)
	}
	return "network"
}

func (d *Daemon) reloadConfig() {
	st := stampOf(d.o.Store.Dir())
	if st == d.cfgStamp {
		return
	}
	d.cfgStamp = st
	c, err := LoadConfig(d.o.Store.Dir())
	if err != nil {
		d.log.Warn("config change ignored", "err", err)
		return
	}
	if c != d.cfg {
		d.log.Info("config reloaded", "mode", c.Mode, "max_text_bytes", c.MaxTextBytes, "max_image_bytes", c.MaxImageBytes)
	}
	d.cfg = c
}

// refreshRoster fetches the relay's roster, verifies it against the held one
// and persists it. A relay-provided roster is never trusted without Verify.
func (d *Daemon) refreshRoster(ctx context.Context, why string) {
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	info, err := d.cl.FetchRoster(fctx)
	if err != nil {
		if ctx.Err() == nil {
			d.log.Debug("roster refresh failed", "why", why, "err_kind", errKind(err))
			d.onErr(ctx, err)
		}
		return
	}
	d.lastRefr = time.Now()
	cur := d.roster()
	r := info.Roster
	if r.Version <= cur.Version {
		return
	}
	if err := r.Verify(cur); err != nil {
		d.log.Warn("relay roster rejected", "why", why, "err", err)
		return
	}
	if _, ok := r.Lookup(d.self); !ok {
		d.log.Warn("verified roster no longer contains this device")
		d.revoke()
		return
	}
	d.rosMu.Lock()
	d.ros = r
	d.rosMu.Unlock()
	d.state.RosterBlob = info.Blob // single-goroutine owner (see Run)
	if err := d.o.Store.UpdateState(func(s *keystore.State) error { s.RosterBlob = info.Blob; return nil }); err != nil {
		d.log.Warn("cannot persist roster", "err", err)
	}
	d.log.Info("roster updated", "version", r.Version, "devices", len(r.Entries))
}

func (d *Daemon) remember(id string) bool {
	if _, ok := d.seen[id]; ok {
		return false
	}
	d.seen[id] = struct{}{}
	d.seenOrder = append(d.seenOrder, id)
	if len(d.seenOrder) > 256 {
		delete(d.seen, d.seenOrder[0])
		d.seenOrder = d.seenOrder[1:]
	}
	return true
}

func (d *Daemon) handleRemote(ctx context.Context, ev client.Event) {
	if !d.remember(ev.ID) {
		return
	}
	if !d.cfg.canReceive() {
		d.log.Debug("item ignored by mode", "mode", d.cfg.Mode)
		return
	}
	// Learn about new devices before opening: an unknown sender is rejected.
	var from [16]byte
	if b, err := hex.DecodeString(ev.From); err == nil && len(b) == 16 {
		copy(from[:], b)
	}
	if _, known := d.roster().Lookup(from); !known || time.Since(d.lastRefr) > 30*time.Second {
		d.refreshRoster(ctx, "event")
	}
	fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	item, err := d.cl.FetchItem(fctx, ev.ID)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			d.log.Warn("item rejected or unavailable", "id", ev.ID, "err", err)
			d.onErr(ctx, err)
		}
		return
	}
	var k clip.Kind
	switch item.CType {
	case envelope.CTypeText:
		k = clip.KindText
		if int64(len(item.Body)) > d.cfg.MaxTextBytes {
			d.log.Warn("received text exceeds max_text_bytes; not applied", "bytes", len(item.Body))
			return
		}
	case envelope.CTypeImagePNG:
		k = clip.KindPNG
		if int64(len(item.Body)) > d.cfg.MaxImageBytes || !bytes.HasPrefix(item.Body, clip.PNGSignature) {
			d.log.Warn("received image rejected (too large or not a PNG)", "bytes", len(item.Body))
			return
		}
	default:
		return
	}
	// Record the hash BEFORE writing: the clipboard watcher will report our own
	// write and must find it here.
	d.lastApplied, d.hasApplied = hashOf(k, item.Body), true
	d.appliedAt[k] = time.Now()
	wctx, wc := context.WithTimeout(ctx, 10*time.Second)
	err = d.o.Clip.Write(wctx, k, item.Body)
	wc()
	if err != nil {
		d.log.Warn("cannot write clipboard", "err", err)
		return
	}
	d.applied.Add(1)
	d.log.Info("clipboard updated from another device", "kind", k.String(), "bytes", len(item.Body))
}

func (d *Daemon) handleLocal(ctx context.Context, e clip.Event) {
	if !d.cfg.canSend() {
		return
	}
	if e.Sensitive {
		return
	}
	if len(e.Data) == 0 {
		return
	}
	var ctype uint8
	switch e.Kind {
	case clip.KindText:
		ctype = envelope.CTypeText
		if int64(len(e.Data)) > d.cfg.MaxTextBytes {
			d.log.Warn("clipboard text is larger than max_text_bytes; not sent", "bytes", len(e.Data), "limit", d.cfg.MaxTextBytes)
			return
		}
		if !utf8.Valid(e.Data) {
			d.log.Warn("clipboard text is not valid UTF-8; not sent")
			return
		}
	case clip.KindPNG:
		ctype = envelope.CTypeImagePNG
		if int64(len(e.Data)) > d.cfg.MaxImageBytes {
			d.log.Warn("clipboard image is larger than max_image_bytes; not sent", "bytes", len(e.Data), "limit", d.cfg.MaxImageBytes)
			return
		}
		if !bytes.HasPrefix(e.Data, clip.PNGSignature) {
			d.log.Warn("clipboard image is not a PNG; not sent")
			return
		}
	default:
		return
	}
	h := hashOf(e.Kind, e.Data)
	if (d.hasApplied && h == d.lastApplied) || (d.hasSent && h == d.lastSent) {
		return // our own write or a repeat
	}
	if w := d.o.EchoWindow; w > 0 && time.Since(d.appliedAt[e.Kind]) < w {
		d.log.Debug("local change right after applying a remote item ignored (echo)")
		return
	}
	// Pick up devices added/removed since the last look so the item is
	// encrypted to the right set.
	if time.Since(d.lastRefr) > 2*time.Second {
		d.refreshRoster(ctx, "before send")
	}
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	ref, err := d.cl.SendItem(sctx, ctype, e.Data)
	cancel()
	switch {
	case err == nil:
		d.lastSent, d.hasSent = h, true
		d.sent.Add(1)
		d.log.Info("clipboard sent", "kind", e.Kind.String(), "bytes", len(e.Data), "id", ref.ID)
	case errors.Is(err, client.ErrNoRecipients):
		d.log.Info("no other devices in the group yet; nothing sent")
	default:
		if ctx.Err() == nil {
			d.log.Warn("send failed", "err", err)
			d.onErr(ctx, err)
		}
	}
}
