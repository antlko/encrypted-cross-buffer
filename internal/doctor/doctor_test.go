package doctor

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

const enroll = "doctor-test-enroll-token-0123456789"

// spy records Authorization tokens and request paths, and can block /v1/ws.
type spy struct {
	h       http.Handler
	mu      sync.Mutex
	tokens  []string
	paths   []string
	blockWS bool
}

func (s *spy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.paths = append(s.paths, r.URL.Path)
	if a := r.Header.Get("Authorization"); a != "" {
		s.tokens = append(s.tokens, strings.TrimPrefix(a, "Bearer "))
	}
	block := s.blockWS && r.URL.Path == "/v1/ws"
	s.mu.Unlock()
	if block {
		http.Error(w, "websocket upgrade not allowed", http.StatusForbidden)
		return
	}
	s.h.ServeHTTP(w, r)
}

type fixture struct {
	spy *spy
	cfg *client.Config
}

// newRelay starts the real relay behind a spy and creates a one-device group.
func newRelay(t *testing.T) *fixture {
	t.Helper()
	srv, err := relay.New(relay.Config{Addr: ":0", DataDir: t.TempDir(), EnrollToken: enroll,
		Limits: relay.DefaultRateLimits()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	sp := &spy{h: srv.Handler()}
	id, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	gid := [16]byte{1, 2, 3}
	ros, err := roster.NewGenesis(gid, roster.NewEntry("A", id.Recipient(), id.PublicKey(), 1), id.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{spy: sp, cfg: &client.Config{
		Identity: id, GroupID: gid, State: &keystore.State{GroupID: gid},
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return ros, nil }),
	}}
	return &fixture{spy: sp, cfg: f.cfg}
}

func (f *fixture) create(t *testing.T, url string, hc *http.Client) {
	t.Helper()
	cfg := *f.cfg
	cfg.BaseURL, cfg.HTTPClient = url, hc
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ros, _ := cfg.Roster.Roster()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.CreateGroup(ctx, enroll, ros); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, o Options) Report {
	t.Helper()
	if o.Duration == 0 {
		o.Duration = time.Second
	}
	if o.PublicDNS == "" {
		o.PublicDNS = "off"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Run(ctx, o)
}

func step(t *testing.T, r Report, id string) Step {
	t.Helper()
	for _, s := range r.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step %q in %+v", id, r.Steps)
	return Step{}
}

func TestHealthyRelayPasses(t *testing.T) {
	f := newRelay(t)
	ts := httptest.NewServer(f.spy)
	defer ts.Close()
	f.create(t, ts.URL, nil)
	rep := run(t, Options{RelayURL: ts.URL, Client: f.cfg})
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict %s (%s): %+v", rep.Verdict, rep.Summary, rep.Steps)
	}
	for _, id := range []string{StepDNS, StepTCP, StepHTTP, StepAuth, StepWebSocket, StepLongPoll} {
		if s := step(t, rep, id); s.Status != OK && s.Status != Skip {
			t.Errorf("%s: %+v", id, s)
		}
	}
	if s := step(t, rep, StepURL); s.Status != Warn || !strings.Contains(s.Detail, "NOT TLS") {
		t.Errorf("url step should warn about plain http: %+v", s)
	}
	if s := step(t, rep, StepPayload); s.Status != Skip {
		t.Errorf("payload: %+v", s)
	}
	// Never leak tokens, the enroll token or key material.
	b, _ := json.Marshal(rep)
	out := string(b)
	f.spy.mu.Lock()
	defer f.spy.mu.Unlock()
	if len(f.spy.tokens) == 0 {
		t.Fatal("expected authenticated requests")
	}
	for _, tok := range f.spy.tokens {
		if tok != "" && strings.Contains(out, tok) {
			t.Fatal("report contains a bearer token")
		}
	}
	for _, bad := range []string{enroll, "Bearer", "AGE-SECRET-KEY", "nonce"} {
		if strings.Contains(out, bad) {
			t.Errorf("report contains %q", bad)
		}
	}
}

func TestWebSocketBlockedFallsBackToLongPoll(t *testing.T) {
	f := newRelay(t)
	f.spy.blockWS = true
	ts := httptest.NewServer(f.spy)
	defer ts.Close()
	f.create(t, ts.URL, nil)
	rep := run(t, Options{RelayURL: ts.URL, Client: f.cfg})
	if rep.Verdict != VerdictFallback {
		t.Fatalf("verdict %s: %s %+v", rep.Verdict, rep.Summary, rep.Steps)
	}
	ws := step(t, rep, StepWebSocket)
	if ws.Status != Fail || !strings.Contains(ws.Hint, "long-poll") {
		t.Errorf("ws: %+v", ws)
	}
	if lp := step(t, rep, StepLongPoll); lp.Status != OK {
		t.Errorf("longpoll: %+v", lp)
	}
}

func TestNoWSFlagSkipsWebSocket(t *testing.T) {
	f := newRelay(t)
	ts := httptest.NewServer(f.spy)
	defer ts.Close()
	f.create(t, ts.URL, nil)
	rep := run(t, Options{RelayURL: ts.URL, Client: f.cfg, NoWS: true})
	if step(t, rep, StepWebSocket).Status != Skip || rep.Verdict != VerdictPass {
		t.Fatalf("%s %+v", rep.Verdict, rep.Steps)
	}
	f.spy.mu.Lock()
	defer f.spy.mu.Unlock()
	for _, p := range f.spy.paths {
		if p == "/v1/ws" {
			t.Fatal("websocket was opened despite NoWS")
		}
	}
}

func TestNotInitializedSkipsAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") }))
	defer ts.Close()
	rep := run(t, Options{RelayURL: ts.URL})
	a := step(t, rep, StepAuth)
	if a.Status != Skip || !strings.Contains(a.Detail, "ecb init") {
		t.Fatalf("auth: %+v", a)
	}
	if rep.Verdict != VerdictPass || !strings.Contains(rep.Summary, "NOT tested") {
		t.Fatalf("%s / %s", rep.Verdict, rep.Summary)
	}
}

func TestSelfSignedCertReportsIssuerWithoutBypass(t *testing.T) {
	var hits int
	var mu sync.Mutex
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		io.WriteString(w, "ok\n")
	}))
	defer ts.Close()
	rep := run(t, Options{RelayURL: ts.URL}) // system roots: the test cert is not trusted
	if rep.Verdict != VerdictFail || rep.FailedStep != StepTLS {
		t.Fatalf("verdict %s step %q: %+v", rep.Verdict, rep.FailedStep, rep.Steps)
	}
	tl := step(t, rep, StepTLS)
	if !strings.Contains(tl.Detail, "NOT trusted") || !strings.Contains(tl.Hint, "inspection") {
		t.Errorf("tls: %+v", tl)
	}
	is := step(t, rep, StepTLSIssuer)
	if !strings.Contains(is.Detail, "Acme Co") || !strings.Contains(is.Detail, "no data sent") || !strings.Contains(is.Hint, "TLS inspection suspected") {
		t.Errorf("issuer step: %+v", is)
	}
	if step(t, rep, StepHTTP).Status != Skip {
		t.Error("http must not run after a TLS failure")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("an HTTP request reached the server (%d): the informational handshake must send no data", hits)
	}
}

func TestTrustedPrivateCAWarnsInspectionSuspected(t *testing.T) {
	f := newRelay(t)
	ts := httptest.NewTLSServer(f.spy)
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	f.create(t, ts.URL, ts.Client())
	rep := run(t, Options{RelayURL: ts.URL, Client: f.cfg, HTTPClient: ts.Client(), RootCAs: pool})
	tl := step(t, rep, StepTLS)
	if tl.Status != Warn || !strings.Contains(tl.Hint, "TLS inspection suspected") || !strings.Contains(tl.Detail, "Acme Co") {
		t.Fatalf("tls: %+v", tl)
	}
	if !strings.Contains(tl.Detail, "TLS 1.3") || !strings.Contains(tl.Detail, "ALPN") {
		t.Errorf("missing version/ALPN: %s", tl.Detail)
	}
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict %s: %+v", rep.Verdict, rep.Steps)
	}
}

func TestHTMLBlockPageFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>\n<body>\x1b[31m  Access   to this site has been BLOCKED by your organisation's security policy. Contact IT.</body></html>")
	}))
	defer ts.Close()
	rep := run(t, Options{RelayURL: ts.URL})
	if rep.Verdict != VerdictFail || rep.FailedStep != StepHTTP {
		t.Fatalf("%s %q", rep.Verdict, rep.FailedStep)
	}
	h := step(t, rep, StepHTTP)
	if !strings.Contains(h.Detail, "<html> <body> [31m Access to this site") || strings.ContainsAny(h.Detail, "\x1b\n") {
		t.Errorf("body not sanitized: %q", h.Detail)
	}
	if strings.Contains(h.Detail, "Contact IT") {
		t.Errorf("body not truncated to 80 chars: %q", h.Detail)
	}
	if !strings.Contains(h.Hint, "block page") {
		t.Errorf("hint: %q", h.Hint)
	}
}

func TestDNSFailure(t *testing.T) {
	rep := run(t, Options{RelayURL: "https://no-such-host.invalid"})
	if rep.Verdict != VerdictFail || rep.FailedStep != StepDNS {
		t.Fatalf("%s %q %+v", rep.Verdict, rep.FailedStep, rep.Steps)
	}
	if !strings.Contains(step(t, rep, StepDNS).Hint, "NordLayer") {
		t.Error("dns hint should mention the VPN DNS policy")
	}
	if step(t, rep, StepTCP).Status != Skip {
		t.Error("tcp must be skipped")
	}
}

func TestClosedPortFailsAtTCP(t *testing.T) {
	rep := run(t, Options{RelayURL: "http://127.0.0.1:1"})
	if rep.Verdict != VerdictFail || rep.FailedStep != StepTCP {
		t.Fatalf("%s %q %+v", rep.Verdict, rep.FailedStep, rep.Steps)
	}
	if step(t, rep, StepDNS).Status != Skip { // IP literal
		t.Errorf("dns: %+v", step(t, rep, StepDNS))
	}
}

func TestURLSanity(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "http://relay.example.com", "https://user:pw@relay.example.com", "not a url"} {
		rep := run(t, Options{RelayURL: u})
		if rep.Verdict != VerdictFail || rep.FailedStep != StepURL {
			t.Errorf("%q: %s %q", u, rep.Verdict, rep.FailedStep)
		}
		if strings.Contains(rep.Relay, "pw") {
			t.Errorf("credentials leaked in report: %q", rep.Relay)
		}
	}
}

func TestJSONSchema(t *testing.T) {
	rep := run(t, Options{RelayURL: "http://127.0.0.1:1"})
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"relay", "steps", "verdict", "failed_step", "summary"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
	}
	steps := m["steps"].([]any)
	if len(steps) == 0 {
		t.Fatal("no steps")
	}
	for _, s := range steps {
		sm := s.(map[string]any)
		for _, k := range []string{"id", "status", "detail", "ms"} {
			if _, ok := sm[k]; !ok {
				t.Errorf("step missing %q: %v", k, sm)
			}
		}
		switch sm["status"] {
		case "OK", "WARN", "FAIL", "SKIP":
		default:
			t.Errorf("bad status %v", sm["status"])
		}
	}
	if m["verdict"] != "FAIL" || m["failed_step"] != "tcp" {
		t.Errorf("verdict/failed_step: %v %v", m["verdict"], m["failed_step"])
	}
}

func TestInterruptedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep := Run(ctx, Options{RelayURL: "http://127.0.0.1:1", PublicDNS: "off"})
	if rep.Verdict != VerdictFail {
		t.Fatalf("%s", rep.Verdict)
	}
}

func TestCleanSanitizes(t *testing.T) {
	got := clean("a\x00b\n\tc  Bearer abc.def  d", 100)
	if got != "a b c bearer [redacted] d" {
		t.Errorf("got %q", got)
	}
	if got := clean(strings.Repeat("x", 200), 80); len(got) != 83 {
		t.Errorf("len %d", len(got))
	}
}
