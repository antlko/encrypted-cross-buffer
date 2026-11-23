package relay

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	errRevoked  = errors.New("device revoked")
	errShutdown = errors.New("server shutting down")
)

// Server is the relay. Use Handler() with an http.Server (see HTTPServer).
type Server struct {
	cfg    Config
	log    *slog.Logger
	now    func() time.Time
	groups *groupStore
	auth   *authState
	items  *spool
	hub    *hub
	pairs  *pairMgr
	lim    struct{ enroll, authIP, authDev, pair, items *limiter }

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mux    *http.ServeMux
}

// New creates the relay, loading persisted groups from cfg.DataDir.
func New(cfg Config, log *slog.Logger) (*Server, error) {
	cfg.defaults()
	if len(cfg.EnrollToken) < MinEnrollTokenLen {
		return nil, errors.New("relay: enroll token too short")
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	gs, err := openGroupStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	sp, err := newSpool(cfg.DataDir, cfg.ItemTTL, cfg.Now)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, now: cfg.Now, groups: gs, items: sp,
		auth: newAuthState(cfg.Now), hub: newHub(), pairs: newPairMgr(cfg.Now)}
	l := cfg.Limits
	s.lim.enroll = newLimiter(l.EnrollFail, s.now)
	s.lim.authIP = newLimiter(l.AuthIP, s.now)
	s.lim.authDev = newLimiter(l.AuthDevice, s.now)
	s.lim.pair = newLimiter(l.Pair, s.now)
	s.lim.items = newLimiter(l.Items, s.now)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.routes()
	s.wg.Add(1)
	go s.sweeper()
	return s, nil
}

// Sweep removes expired items, nonces, tokens, mailboxes and idle limiter buckets.
func (s *Server) Sweep() {
	s.items.sweep()
	s.auth.sweep()
	s.pairs.sweep()
	for _, l := range []*limiter{s.lim.enroll, s.lim.authIP, s.lim.authDev, s.lim.pair, s.lim.items} {
		l.sweep()
	}
}

func (s *Server) sweeper() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Close cancels websockets/long-polls and stops background goroutines. Call it
// before http.Server.Shutdown so hijacked connections end.
func (s *Server) Close() {
	s.cancel()
	s.wg.Wait()
}

// Handler returns the HTTP handler (with request logging and panic recovery).
func (s *Server) Handler() http.Handler { return s.middleware(s.mux) }

// HTTPServer returns an http.Server with the hardened timeouts. There is no
// read/write timeout: item, websocket and long-poll handlers set their own
// deadlines through http.ResponseController.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok\n")
	})
	m.HandleFunc("POST /v1/groups", s.createGroup)
	m.HandleFunc("POST /v1/groups/{gid}/roster", s.authed(false, s.publishRoster))
	m.HandleFunc("GET /v1/groups/{gid}/roster", s.authed(false, s.getRoster))
	m.HandleFunc("POST /v1/auth/challenge", s.challenge)
	m.HandleFunc("POST /v1/auth/token", s.token)
	m.HandleFunc("POST /v1/items", s.authed(false, s.postItem))
	m.HandleFunc("GET /v1/items/{id}", s.authed(false, s.getItem))
	m.HandleFunc("GET /v1/ws", s.authed(true, s.ws))
	m.HandleFunc("GET /v1/events", s.authed(false, s.events))
	m.HandleFunc("POST /v1/pair", s.authed(false, s.pairCreate))
	m.HandleFunc("POST /v1/pair/{mailbox}/msg", s.pairPost)
	m.HandleFunc("GET /v1/pair/{mailbox}/msg", s.pairGet)
	m.HandleFunc("DELETE /v1/pair/{mailbox}", s.pairBurn)
	s.mux = m
}

// ---- middleware / helpers ------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil && w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return c, rw, err
}

// middleware adds a request id and logs id, route, status and sizes only. It
// never logs headers, query strings, bodies or client addresses.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := randHex(6)
		w.Header().Set("X-Request-Id", rid)
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "rid", rid)
				if sw.status == 0 {
					writeErr(sw, 500, "internal error")
				}
			}
			s.log.Info("request", "rid", rid, "method", r.Method, "route", r.Pattern,
				"status", sw.status, "bytes_in", max(r.ContentLength, 0), "bytes_out", sw.n,
				"dur_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(sw, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func ctrlDeadlines(w http.ResponseWriter, d time.Duration) *http.ResponseController {
	rc := http.NewResponseController(w)
	t := time.Now().Add(d)
	_ = rc.SetReadDeadline(t)
	_ = rc.SetWriteDeadline(t)
	return rc
}

// readJSON decodes a size-limited JSON body with a short read deadline.
func readJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	ctrlDeadlines(w, 20*time.Second)
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid request")
		}
		return false
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		cand := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
		if cand == "" {
			cand, _, _ = strings.Cut(r.Header.Get("X-Forwarded-For"), ",")
			cand = strings.TrimSpace(cand)
		}
		if ip, err := net.ResolveIPAddr("ip", cand); err == nil && cand != "" {
			return ip.IP.String()
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// connCtx is cancelled with errRevoked when the device is removed, or with
// errShutdown when the server closes.
func (s *Server) connCtx(r *http.Request, sess *session) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	untrack := s.hub.track(sess.gid, sess.pub, cancel)
	stop := context.AfterFunc(s.ctx, func() { cancel(errShutdown) })
	return ctx, func() { stop(); untrack(); cancel(nil) }
}

func (s *Server) authed(allowQuery bool, h func(http.ResponseWriter, *http.Request, *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r, allowQuery)
		var sess *session
		if tok != "" {
			sess = s.auth.lookup(tok)
		}
		if sess == nil || !s.groups.has(sess.gid, sess.pub) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h(w, r, sess)
	}
}

func parseGID(s string) ([16]byte, bool) {
	var g [16]byte
	if !isHex(s, 32) {
		return g, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return g, false
	}
	copy(g[:], b)
	return g, true
}

func tokenEqual(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
