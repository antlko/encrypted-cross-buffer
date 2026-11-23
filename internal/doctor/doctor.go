// Package doctor runs layered connectivity diagnostics against an ecb relay
// (URL, DNS, TCP, TLS, HTTP, auth, WebSocket, long-poll) and reports WHICH
// layer fails, in plain language. It never prints tokens, keys, nonces or the
// enrollment token, never sets InsecureSkipVerify for the relay checks and
// never sends items into the user's real group.
package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
)

// Status of one step.
type Status string

// Step statuses.
const (
	OK   Status = "OK"
	Warn Status = "WARN"
	Fail Status = "FAIL"
	Skip Status = "SKIP"
)

// Verdicts.
const (
	VerdictPass     = "PASS"
	VerdictFallback = "PASS-WITH-FALLBACK"
	VerdictFail     = "FAIL"
)

// Step IDs, in execution order.
const (
	StepURL        = "url"
	StepDNS        = "dns"
	StepDNSPublic  = "dns-public"
	StepTCP        = "tcp"
	StepTLS        = "tls"
	StepTLSIssuer  = "tls-issuer"
	StepHTTP       = "http"
	StepAuth       = "auth"
	StepWebSocket  = "websocket"
	StepLongPoll   = "longpoll"
	StepPayload    = "payload"
	defaultStepMax = 10 * time.Second
)

// Step is the result of one check.
type Step struct {
	ID       string `json:"id"`
	Status   Status `json:"status"`
	Detail   string `json:"detail"`
	Hint     string `json:"hint,omitempty"` // what to do (failures and warnings)
	Millis   int64  `json:"ms"`
	Optional bool   `json:"optional,omitempty"` // informational only; never decides the verdict
}

// Report is the whole run.
type Report struct {
	Relay      string `json:"relay"` // scheme://host[:port] only
	Steps      []Step `json:"steps"`
	Verdict    string `json:"verdict"`
	FailedStep string `json:"failed_step,omitempty"`
	Summary    string `json:"summary"`
}

// Options configures Run.
type Options struct {
	RelayURL string
	Duration time.Duration // WebSocket hold time (default 60s)
	NoWS     bool          // skip the WebSocket hold
	// StepTimeout bounds every step except the WebSocket hold (default 10s).
	StepTimeout time.Duration

	// Client is a template for the authenticated steps; nil means this device
	// is not set up. Doctor sets BaseURL, Transport and PollWait itself.
	Client *client.Config
	// NoClientReason explains (to the user) why Client is nil.
	NoClientReason string

	HTTPClient *http.Client   // default client.NewHTTPClient()
	RootCAs    *x509.CertPool // nil = system roots (tests inject a pool; verification stays ON)
	// PublicDNS is the optional comparison resolver (default "1.1.1.1:53";
	// "off" disables it). Only used after the system resolver failed.
	PublicDNS string

	// Progress is called as each step completes; Note for live lines inside
	// a long step. Both may be nil.
	Progress func(Step)
	Note     func(string)
}

type runner struct {
	o      Options
	rep    Report
	scheme string
	host   string
	port   string
	isIP   bool
	tls    bool
	local  bool

	tlsVerifyFailure bool
	interrupted      bool
}

var bearerRe = regexp.MustCompile(`(?i)bearer\s+\S+`)

// Run executes all steps and returns the report. It stops early (remaining
// steps SKIP) when a layer fails, because later layers cannot work then.
func Run(ctx context.Context, o Options) Report {
	if o.Duration <= 0 {
		o.Duration = 60 * time.Second
	}
	if o.StepTimeout <= 0 {
		o.StepTimeout = defaultStepMax
	}
	if o.HTTPClient == nil {
		o.HTTPClient = client.NewHTTPClient()
	}
	if o.PublicDNS == "" {
		o.PublicDNS = "1.1.1.1:53"
	}
	r := &runner{o: o}
	r.run(ctx)
	r.interrupted = ctx.Err() != nil
	r.finish()
	return r.rep
}

func (r *runner) note(s string) {
	if r.o.Note != nil {
		r.o.Note(s)
	}
}

func (r *runner) add(s Step) Step {
	r.rep.Steps = append(r.rep.Steps, s)
	if r.o.Progress != nil {
		r.o.Progress(s)
	}
	return s
}

func (r *runner) skip(id, why string) { r.add(Step{ID: id, Status: Skip, Detail: why}) }

// timed runs fn with a per-step timeout and records its duration.
func (r *runner) timed(ctx context.Context, fn func(ctx context.Context) Step) Step {
	sctx, cancel := context.WithTimeout(ctx, r.o.StepTimeout)
	defer cancel()
	t0 := time.Now()
	s := fn(sctx)
	s.Millis = time.Since(t0).Milliseconds()
	return r.add(s)
}

func (r *runner) failed() bool {
	for _, s := range r.rep.Steps {
		if s.Status == Fail && !s.Optional {
			return true
		}
	}
	return false
}

func (r *runner) skipRest(ids ...string) {
	for _, id := range ids {
		r.skip(id, "not tried because an earlier step failed")
	}
}

func (r *runner) run(ctx context.Context) {
	r.timed(ctx, r.stepURL)
	if r.failed() {
		r.skipRest(StepDNS, StepTCP, StepTLS, StepHTTP, StepAuth, StepWebSocket, StepLongPoll, StepPayload)
		return
	}
	dns := r.timed(ctx, r.stepDNS)
	if dns.Status == Fail {
		r.timed(ctx, r.stepDNSPublic)
		r.skipRest(StepTCP, StepTLS, StepHTTP, StepAuth, StepWebSocket, StepLongPoll, StepPayload)
		return
	}
	if ctx.Err() != nil {
		return
	}
	if r.timed(ctx, r.stepTCP).Status == Fail {
		r.skipRest(StepTLS, StepHTTP, StepAuth, StepWebSocket, StepLongPoll, StepPayload)
		return
	}
	if r.tls {
		tl := r.timed(ctx, r.stepTLS)
		if tl.Status == Fail {
			if r.tlsVerifyFailure {
				r.timed(ctx, r.stepTLSIssuer)
			}
			r.skipRest(StepHTTP, StepAuth, StepWebSocket, StepLongPoll, StepPayload)
			return
		}
	} else {
		r.skip(StepTLS, "not used (plain http to this machine)")
	}
	if r.timed(ctx, r.stepHTTP).Status == Fail {
		r.skipRest(StepAuth, StepWebSocket, StepLongPoll, StepPayload)
		return
	}
	if r.o.Client == nil {
		why := r.o.NoClientReason
		if why == "" {
			why = "this device is not set up: run `ecb init` (first device) or `ecb join` (additional device) first"
		}
		r.skip(StepAuth, why)
		r.skip(StepWebSocket, "needs a set-up device (see the auth step)")
		r.skip(StepLongPoll, "needs a set-up device (see the auth step)")
		r.skip(StepPayload, payloadWhy)
		return
	}
	cfg := *r.o.Client
	cfg.BaseURL = r.base()
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = r.o.HTTPClient
	}
	if r.timed(ctx, func(c context.Context) Step { return r.stepAuth(c, cfg) }).Status == Fail {
		r.skipRest(StepWebSocket, StepLongPoll, StepPayload)
		return
	}
	if ctx.Err() != nil {
		return
	}
	if r.o.NoWS {
		r.skip(StepWebSocket, "skipped by --no-ws")
	} else {
		r.stepWebSocket(ctx, cfg)
	}
	if ctx.Err() != nil {
		return
	}
	r.timed(ctx, func(c context.Context) Step { return r.stepLongPoll(c, cfg) })
	r.skip(StepPayload, payloadWhy)
}

const payloadWhy = "not tested: the relay has no safe probe endpoint and doctor never sends fake items into your real group. " +
	"If large images fail to sync while everything above is OK, a proxy is limiting request size"

func (r *runner) base() string { return r.scheme + "://" + net.JoinHostPort(r.host, r.port) }

// ---- finish ----------------------------------------------------------------

func (r *runner) finish() {
	byID := map[string]Step{}
	for _, s := range r.rep.Steps {
		byID[s.ID] = s
	}
	rep := &r.rep
	if r.rep.Relay == "" && r.host != "" {
		rep.Relay = r.base()
	}
	if r.interrupted {
		rep.Verdict, rep.FailedStep, rep.Summary = VerdictFail, "interrupted", "FAIL: interrupted before all steps finished"
		return
	}
	for _, s := range rep.Steps {
		if s.Status == Fail && !s.Optional && s.ID != StepWebSocket && s.ID != StepLongPoll {
			rep.Verdict, rep.FailedStep = VerdictFail, s.ID
			rep.Summary = fmt.Sprintf("FAIL at step %q: %s", s.ID, s.Detail)
			return
		}
	}
	ws, lp := byID[StepWebSocket], byID[StepLongPoll]
	switch {
	case ws.Status == Fail && lp.Status == OK:
		rep.Verdict = VerdictFallback
		rep.Summary = "PASS-WITH-FALLBACK: WebSocket is blocked but long-poll works; ecb will switch to long-poll automatically (slightly higher latency)"
	case ws.Status == Fail:
		rep.Verdict, rep.FailedStep = VerdictFail, StepLongPoll
		rep.Summary = "FAIL: both WebSocket and long-poll are blocked, so live sync will not work on this network"
	case lp.Status == Fail:
		rep.Verdict, rep.FailedStep = VerdictFail, StepLongPoll
		rep.Summary = "FAIL at step \"longpoll\": " + lp.Detail
	case ws.Status == OK || ws.Status == Warn:
		rep.Verdict = VerdictPass
		rep.Summary = "PASS: the relay path works (DNS, TCP, TLS, HTTP, auth, WebSocket and long-poll)"
		if ws.Status == Warn || lp.Status == Warn {
			rep.Summary = "PASS: the relay path works, with warnings (see above)"
		}
	default:
		rep.Verdict = VerdictPass
		if byID[StepAuth].Status == Skip {
			rep.Summary = "PASS: the relay is reachable from here; login/WebSocket were NOT tested (" + shortWhy(byID[StepAuth].Detail) + ")"
		} else {
			rep.Summary = "PASS: the relay is reachable from here; WebSocket/long-poll were not tested"
		}
	}
}

func shortWhy(s string) string {
	if i := strings.Index(s, ":"); i > 0 && len(s) > 60 {
		return s[:i]
	}
	return s
}

const interruptedMsg = "interrupted"

// ---- step 1: URL -------------------------------------------------------------

func isLocalHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func (r *runner) stepURL(context.Context) Step {
	s := Step{ID: StepURL}
	u, err := url.Parse(strings.TrimSpace(r.o.RelayURL))
	if r.o.RelayURL == "" {
		s.Status, s.Detail = Fail, "no relay URL given"
		s.Hint = "pass --relay https://your-relay.example.com, or set ECB_RELAY, or run `ecb init`/`ecb join` first so the URL is saved"
		return s
	}
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		s.Status, s.Detail = Fail, "not a valid http(s) URL"
		s.Hint = "use a URL like https://ecb.example.com"
		return s
	}
	if u.User != nil {
		s.Status, s.Detail = Fail, "the URL contains a user name/password"
		s.Hint = "remove credentials from the URL; ecb never needs them there"
		return s
	}
	r.scheme, r.host = u.Scheme, u.Hostname()
	r.port = u.Port()
	if r.port == "" {
		r.port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	r.isIP = net.ParseIP(r.host) != nil
	r.local = isLocalHost(r.host)
	r.tls = u.Scheme == "https"
	r.rep.Relay = r.base()
	switch {
	case r.tls:
		s.Status, s.Detail = OK, fmt.Sprintf("https, host %s, port %s", r.host, r.port)
	case r.local:
		s.Status = Warn
		s.Detail = fmt.Sprintf("plain http to %s: this traffic is NOT TLS-encrypted (fine for testing on this machine)", r.host)
		s.Hint = "for a real relay use https://"
	default:
		s.Status, s.Detail = Fail, "plain http to a remote host is not allowed"
		s.Hint = "use https:// (a Cloudflare Tunnel hostname already has HTTPS)"
	}
	return s
}

// ---- step 2: DNS -------------------------------------------------------------

func (r *runner) stepDNS(ctx context.Context) Step {
	s := Step{ID: StepDNS}
	if r.isIP {
		s.Status, s.Detail = Skip, "the URL uses an IP address, no DNS needed"
		return s
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, r.host)
	if err != nil || len(addrs) == 0 {
		s.Status = Fail
		s.Detail = fmt.Sprintf("cannot resolve %s: %s", r.host, cleanErr(err))
		s.Hint = "Check the spelling of the relay host. If it is right, your VPN's DNS policy (NordLayer) may block or not know this name: ask IT to allow it, or check that the VPN's DNS servers are reachable."
		return s
	}
	s.Status, s.Detail = OK, fmt.Sprintf("%s -> %s", r.host, joinMax(addrs, 6))
	return s
}

func (r *runner) stepDNSPublic(ctx context.Context) Step {
	s := Step{ID: StepDNSPublic, Optional: true}
	if r.o.PublicDNS == "off" {
		s.Status, s.Detail = Skip, "disabled"
		return s
	}
	addr := r.o.PublicDNS
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	}}
	addrs, err := res.LookupHost(ctx, r.host)
	if err != nil || len(addrs) == 0 {
		s.Status = Warn
		s.Detail = fmt.Sprintf("optional check: the public resolver %s cannot resolve it either (%s)", addr, dnsReason(err))
		s.Hint = "The name probably does not exist (typo, or the tunnel hostname was removed), or outside DNS is blocked entirely."
		return s
	}
	s.Status = Warn
	s.Detail = fmt.Sprintf("optional check: the public resolver %s resolves it to %s, but your system resolver does not", addr, joinMax(addrs, 6))
	s.Hint = "Your network's DNS is the problem (NordLayer/corporate DNS policy). Ask IT to allow this hostname, or change the VPN's DNS setting."
	return s
}

// ---- step 3: TCP -------------------------------------------------------------

func (r *runner) stepTCP(ctx context.Context) Step {
	s := Step{ID: StepTCP}
	d := net.Dialer{}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.host, r.port))
	if err != nil {
		s.Status = Fail
		s.Detail = fmt.Sprintf("cannot connect to %s:%s: %s", r.host, r.port, cleanErr(err))
		s.Hint = "Nothing answered on that port. Check the port, that the relay/tunnel is running, and that your VPN or firewall allows outbound connections to port " + r.port + "."
		return s
	}
	_ = conn.Close()
	s.Status = OK
	s.Detail = fmt.Sprintf("connected to %s in %d ms", conn.RemoteAddr(), time.Since(t0).Milliseconds())
	return s
}

// ---- step 4: TLS -------------------------------------------------------------

var publicCAs = []string{"let's encrypt", "isrg", "google trust", "cloudflare", "digicert", "sectigo", "comodo", "globalsign",
	"amazon", "microsoft", "godaddy", "starfield", "entrust", "ssl.com", "buypass", "zerossl", "baltimore", "usertrust", "certum"}

func orgOf(n interface{ String() string }, orgs []string, cn string) string {
	if len(orgs) > 0 {
		return strings.Join(orgs, ", ")
	}
	if cn != "" {
		return cn
	}
	return n.String()
}

func certName(c *x509.Certificate) (subject, issuer string) {
	return orgOf(c.Subject, c.Subject.Organization, c.Subject.CommonName),
		orgOf(c.Issuer, c.Issuer.Organization, c.Issuer.CommonName)
}

func looksPublic(names ...string) bool {
	for _, n := range names {
		l := strings.ToLower(n)
		for _, p := range publicCAs {
			if strings.Contains(l, p) {
				return true
			}
		}
	}
	return false
}

func (r *runner) tlsConfig(insecure bool) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, RootCAs: r.o.RootCAs}
	if !r.isIP {
		c.ServerName = r.host
	}
	if insecure {
		c.InsecureSkipVerify = true //nolint:gosec // issuer read only; no data is ever sent (see stepTLSIssuer)
	}
	return c
}

func isVerifyErr(err error) bool {
	var (
		ua x509.UnknownAuthorityError
		ci x509.CertificateInvalidError
		he x509.HostnameError
		cv *tls.CertificateVerificationError
	)
	return errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &he) || errors.As(err, &cv)
}

func (r *runner) stepTLS(ctx context.Context) Step {
	s := Step{ID: StepTLS}
	d := tls.Dialer{Config: r.tlsConfig(false)}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.host, r.port))
	if err != nil {
		s.Status = Fail
		if isVerifyErr(err) {
			r.tlsVerifyFailure = true
			s.Detail = "the certificate is NOT trusted by this computer: " + cleanErr(err)
			s.Hint = "TLS inspection by a corporate proxy/VPN is likely (it re-signs HTTPS with its own certificate), or the hostname/certificate is wrong. Ask IT to exempt this hostname from inspection or to give you the company root CA; ecb will not bypass certificate checks."
		} else {
			s.Detail = "TLS handshake failed: " + cleanErr(err)
			s.Hint = "The connection opened but the secure handshake did not finish. A firewall or proxy may be dropping or blocking TLS to this host; try from another network to compare."
		}
		return s
	}
	defer conn.Close()
	st := conn.(*tls.Conn).ConnectionState()
	proto := st.NegotiatedProtocol
	if proto == "" {
		proto = "none (http/1.1)"
	}
	leaf := st.PeerCertificates[0]
	subj, iss := certName(leaf)
	rootOrg := ""
	if len(st.VerifiedChains) > 0 {
		ch := st.VerifiedChains[0]
		_, rootOrg = certName(ch[len(ch)-1])
	}
	s.Status = OK
	s.Detail = fmt.Sprintf("%s, ALPN %s, certificate for %q issued by %q (chain verified with system roots) in %d ms",
		tlsVersion(st.Version), proto, subj, iss, time.Since(t0).Milliseconds())
	if !looksPublic(iss, rootOrg) {
		s.Status = Warn
		s.Detail += fmt.Sprintf("; chain root %q", rootOrg)
		s.Hint = "TLS inspection suspected: the issuer is not a well-known public CA. Your company may be decrypting HTTPS (its CA is installed on this laptop). Syncing still works because item content is end-to-end encrypted, but WebSocket may be affected."
	}
	return s
}

// stepTLSIssuer repeats the handshake WITHOUT verification only to read the
// certificate issuer after a verification failure. No application data is sent.
func (r *runner) stepTLSIssuer(ctx context.Context) Step {
	s := Step{ID: StepTLSIssuer, Optional: true}
	d := tls.Dialer{Config: r.tlsConfig(true)}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.host, r.port))
	if err != nil {
		s.Status, s.Detail = Skip, "informational handshake (verification off, no data sent) failed: "+cleanErr(err)
		return s
	}
	st := conn.(*tls.Conn).ConnectionState()
	_ = conn.Close()
	if len(st.PeerCertificates) == 0 {
		s.Status, s.Detail = Skip, "no certificate received"
		return s
	}
	subj, iss := certName(st.PeerCertificates[0])
	s.Status = Warn
	s.Detail = fmt.Sprintf("informational only (verification disabled, no data sent): certificate for %q issued by %q", subj, iss)
	if looksPublic(iss) {
		s.Hint = "The issuer looks like a public CA, so the failure may be a wrong hostname or an expired certificate."
	} else {
		s.Hint = "TLS inspection suspected: the issuer is not a well-known public CA. Show this issuer name to IT and ask for the company root CA to be installed, or for this hostname to be exempt from inspection."
	}
	return s
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return fmt.Sprintf("TLS 0x%04x", v)
}

// ---- step 5: HTTP --------------------------------------------------------------

func (r *runner) stepHTTP(ctx context.Context) Step {
	s := Step{ID: StepHTTP}
	hc := *r.o.HTTPClient
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base()+"/healthz", nil)
	if err != nil {
		s.Status, s.Detail = Fail, cleanErr(err)
		return s
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		s.Status = Fail
		s.Detail = "GET /healthz failed: " + cleanErr(err)
		s.Hint = "The network path works up to TLS but the HTTP request failed. A proxy may be interrupting it, or the relay/tunnel is down."
		return s
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	lat := time.Since(t0).Milliseconds()
	cf := "no"
	if resp.Header.Get("CF-Ray") != "" {
		cf = "yes"
	}
	server := clean(resp.Header.Get("Server"), 40)
	if server == "" {
		server = "-"
	}
	meta := fmt.Sprintf("%s, %d ms, Cloudflare CF-Ray header: %s, Server: %s", resp.Proto, lat, cf, server)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		s.Status = Fail
		s.Detail = fmt.Sprintf("GET /healthz returned HTTP %d, not the relay's \"ok\" (%s); body starts: %q", resp.StatusCode, meta, clean(string(body), 80))
		switch {
		case resp.StatusCode >= 520 && resp.StatusCode <= 530 || resp.StatusCode == 502 || resp.StatusCode == 530:
			s.Hint = "Cloudflare answered but cannot reach your relay: check that the relay and cloudflared are running on the server."
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			s.Hint = "You are being redirected (e.g. to a login or block page). A proxy or captive portal is probably in the way."
		default:
			s.Hint = "This does not look like the relay. A corporate filter may be showing a block page, or the URL points at a different service."
		}
		return s
	}
	s.Status, s.Detail = OK, "/healthz answered \"ok\" ("+meta+")"
	if r.tls && !r.local && cf == "no" {
		s.Detail += "; no Cloudflare headers seen (fine if you do not use Cloudflare)"
	}
	return s
}

// ---- step 6a: auth ------------------------------------------------------------

func (r *runner) stepAuth(ctx context.Context, cfg client.Config) Step {
	s := Step{ID: StepAuth}
	c, err := client.New(cfg)
	if err != nil {
		s.Status, s.Detail = Fail, "cannot set up the client: "+cleanErr(err)
		return s
	}
	t0 := time.Now()
	if err := c.Authenticate(ctx); err != nil {
		s.Status = Fail
		if client.IsStatus(err, 401) || client.IsStatus(err, 403) || client.IsStatus(err, 404) {
			s.Detail = "the relay refused this device: " + cleanErr(err)
			s.Hint = "This device may have been removed from the group, or the relay was reset. Run `ecb status`; if needed re-join with `ecb pair` on another device and `ecb join` here."
		} else {
			s.Detail = "login (challenge/response) failed: " + cleanErr(err)
			s.Hint = "HTTPS GET worked but this request did not. A proxy may block POST requests, or the relay returned an error."
		}
		return s
	}
	s.Status, s.Detail = OK, fmt.Sprintf("this device authenticated in %d ms", time.Since(t0).Milliseconds())
	return s
}

// ---- step 6b: websocket ---------------------------------------------------------

type wsProbe struct {
	mu      sync.Mutex
	ever    bool
	up      bool
	drops   []string
	first   error
	failed  chan struct{}
	once    sync.Once
	note    func(string)
	t0      time.Time
	upAfter time.Duration
}

func (p *wsProbe) Name() string { return "doctor-websocket" }

func (p *wsProbe) say(s string) {
	if p.note != nil {
		p.note(s)
	}
}

func (p *wsProbe) Run(ctx context.Context, c *client.Client, sink *client.Sink, connected func()) error {
	err := client.WebSocket{}.Run(ctx, c, sink, func() {
		p.mu.Lock()
		again := p.ever
		if !p.ever {
			p.upAfter = time.Since(p.t0)
		}
		p.ever, p.up = true, true
		p.mu.Unlock()
		if again {
			p.say("ws re-established")
		} else {
			p.say(fmt.Sprintf("ws up after %d ms", p.upAfter.Milliseconds()))
		}
		connected()
	})
	if ctx.Err() != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case !p.ever:
		p.first = err
		p.once.Do(func() { close(p.failed) })
	case p.up:
		p.drops = append(p.drops, cleanErr(err))
		p.say("ws dropped: " + cleanErr(err) + " (client will reconnect)")
	default:
		p.drops = append(p.drops, "reconnect failed: "+cleanErr(err))
	}
	p.up = false
	return err
}

func (r *runner) stepWebSocket(ctx context.Context, cfg client.Config) {
	s := Step{ID: StepWebSocket}
	p := &wsProbe{failed: make(chan struct{}), note: r.note, t0: time.Now()}
	cfg.Transport = p
	c, err := client.New(cfg)
	if err != nil {
		s.Status, s.Detail = Fail, cleanErr(err)
		r.add(s)
		return
	}
	ping := cfg.PingInterval
	if ping <= 0 {
		ping = 25 * time.Second
	}
	r.note(fmt.Sprintf("opening the WebSocket and holding it for %s (client keepalive ping every %s)", r.o.Duration, ping))
	wctx, cancel := context.WithCancel(ctx)
	ch := c.Events(wctx)
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	t0 := time.Now()
	timer := time.NewTimer(r.o.Duration)
	failed := false
	select {
	case <-timer.C:
	case <-p.failed:
		failed = true
	case <-ctx.Done():
	}
	timer.Stop()
	held := time.Since(t0)
	cancel()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
	}
	s.Millis = held.Milliseconds()
	p.mu.Lock()
	defer func() { p.mu.Unlock(); r.add(s) }()
	switch {
	case ctx.Err() != nil:
		s.Status, s.Detail = Skip, interruptedMsg
	case failed || !p.ever:
		s.Status = Fail
		s.Detail = "the WebSocket could not be opened: " + cleanErr(p.first)
		s.Hint = "A proxy or firewall (or TLS inspection) is probably blocking WebSocket upgrades. This is OK: ecb falls back to long-poll automatically (see the next step), with slightly higher latency."
	case len(p.drops) > 0:
		s.Status = Warn
		s.Detail = fmt.Sprintf("the WebSocket came up after %d ms but dropped %d time(s) in %s: %s", p.upAfter.Milliseconds(), len(p.drops), held.Round(time.Second), strings.Join(p.drops, "; "))
		s.Hint = "Something on the path closes idle connections. ecb reconnects automatically, so it keeps working, but clips may arrive with a short delay."
	default:
		pings := int(held / ping)
		s.Status = OK
		s.Detail = fmt.Sprintf("ws up after %d ms and held for %s with no drops; %d keepalive ping(s) answered", p.upAfter.Milliseconds(), held.Round(time.Second), pings)
		if pings == 0 {
			s.Detail += " (hold time shorter than the ping interval: use --duration 60s or more to test idle timeouts)"
		}
	}
}

// ---- step 7: long-poll ------------------------------------------------------------

func (r *runner) stepLongPoll(ctx context.Context, cfg client.Config) Step {
	s := Step{ID: StepLongPoll}
	up := make(chan struct{})
	var once sync.Once
	cfg.Transport = longPollProbe{up: func() { once.Do(func() { close(up) }) }}
	cfg.PollWait = 3 * time.Second
	c, err := client.New(cfg)
	if err != nil {
		s.Status, s.Detail = Fail, cleanErr(err)
		return s
	}
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	t0 := time.Now()
	ch := c.Events(lctx)
	go func() {
		for range ch {
		}
	}()
	select {
	case <-up:
		s.Status = OK
		s.Detail = fmt.Sprintf("GET /v1/events?wait=3 answered in %d ms: the long-poll fallback works on this network", time.Since(t0).Milliseconds())
	case <-ctx.Done():
		s.Status = Fail
		s.Detail = "no answer to GET /v1/events?wait=3 within the time limit"
		s.Hint = "Long-poll responses may be buffered or cut by a proxy. Try again; if it repeats, ask IT about proxy timeouts for this host."
	}
	if s.Status == Fail && r.wsOK() {
		s.Status = Warn
		s.Hint = "The WebSocket works, so syncing is fine; only the fallback path is affected."
	}
	return s
}

func (r *runner) wsOK() bool {
	for _, st := range r.rep.Steps {
		if st.ID == StepWebSocket {
			return st.Status == OK || st.Status == Warn
		}
	}
	return false
}

type longPollProbe struct{ up func() }

func (longPollProbe) Name() string { return "doctor-longpoll" }
func (p longPollProbe) Run(ctx context.Context, c *client.Client, sink *client.Sink, connected func()) error {
	return client.LongPoll{}.Run(ctx, c, sink, func() { p.up(); connected() })
}

// ---- helpers ---------------------------------------------------------------------

// clean makes s safe and short for one terminal line.
func clean(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := bearerRe.ReplaceAllString(b.String(), "bearer [redacted]")
	if rs := []rune(out); len(rs) > max {
		out = string(rs[:max]) + "..."
	}
	return out
}

func cleanErr(err error) string {
	if err == nil {
		return "unknown error"
	}
	return clean(err.Error(), 240)
}

func joinMax(a []string, n int) string {
	if len(a) > n {
		return strings.Join(a[:n], ", ") + fmt.Sprintf(" (+%d more)", len(a)-n)
	}
	return strings.Join(a, ", ")
}

// dnsReason is a short cause for a failed lookup (the Go error text names the
// system resolver, which is misleading for the custom-dial public check).
func dnsReason(err error) string {
	var de *net.DNSError
	switch {
	case errors.As(err, &de) && de.IsNotFound:
		return "no such host"
	case errors.As(err, &de) && de.IsTimeout:
		return "timed out"
	}
	return "no answer"
}
