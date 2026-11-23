// Package client is the Go client of the ecb relay: group creation, device
// authentication (auto-refreshing tokens), roster publish/fetch, item
// send/fetch (envelope sealed/opened), the event stream (WebSocket with
// long-poll fallback) and the pairing mailbox helpers.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/relay"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

// RosterProvider returns the device's current verified roster (recipients and
// sender keys come from it).
type RosterProvider interface {
	Roster() (*roster.Roster, error)
}

// RosterFunc adapts a function to RosterProvider.
type RosterFunc func() (*roster.Roster, error)

// Roster implements RosterProvider.
func (f RosterFunc) Roster() (*roster.Roster, error) { return f() }

// Config configures a Client.
type Config struct {
	BaseURL  string // relay base URL, e.g. https://ecb.example.com
	Identity *keystore.Identity
	GroupID  [16]byte
	Roster   RosterProvider
	// State holds send/receive counters; required for SendItem/FetchItem.
	State *keystore.State
	// Store, if set, persists State after each counter change.
	Store *keystore.Store

	HTTPClient *http.Client // default NewHTTPClient(); TLS verification is always on by default
	Logger     *slog.Logger
	Now        func() time.Time // clock for envelope timestamps (tests)
	TTL        time.Duration    // item TTL used when opening (default 10m)
	Limits     envelope.Limits

	// Event stream tuning (defaults: 25s, 1s, 30s, 3, 5m, 25s).
	PingInterval         time.Duration
	BackoffMin           time.Duration
	BackoffMax           time.Duration
	WSFailuresBeforePoll int
	WSRetryAfter         time.Duration
	PollWait             time.Duration
	// Transport overrides the default (WebSocket with long-poll fallback).
	Transport Transport
}

// Client talks to one relay as one device of one group.
type Client struct {
	cfg  Config
	base *url.URL
	hc   *http.Client
	log  *slog.Logger
	gid  string // hex
	pub  ed25519.PublicKey

	authMu sync.Mutex // serialises token refresh
	tokMu  sync.Mutex
	token  string
	tokExp time.Time

	stMu sync.Mutex // guards cfg.State
}

// NewHTTPClient returns the default HTTP client: TLS verification on, HTTP/2
// negotiated by ALPN, sane dial/handshake timeouts and no overall timeout
// (streams and long-polls are bounded by contexts).
func NewHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          10,
	}
	return &http.Client{Transport: tr}
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Identity == nil || cfg.Identity.X25519 == nil || len(cfg.Identity.Ed25519) != ed25519.PrivateKeySize {
		return nil, errors.New("client: identity required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("client: BaseURL must be an http(s) URL")
	}
	c := &Client{cfg: cfg, base: u, hc: cfg.HTTPClient, log: cfg.Logger,
		gid: hex.EncodeToString(cfg.GroupID[:]), pub: cfg.Identity.PublicKey()}
	if c.hc == nil {
		c.hc = NewHTTPClient()
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if c.cfg.Now == nil {
		c.cfg.Now = time.Now
	}
	if c.cfg.PingInterval <= 0 {
		c.cfg.PingInterval = 25 * time.Second
	}
	if c.cfg.BackoffMin <= 0 {
		c.cfg.BackoffMin = time.Second
	}
	if c.cfg.BackoffMax <= 0 {
		c.cfg.BackoffMax = 30 * time.Second
	}
	if c.cfg.WSFailuresBeforePoll <= 0 {
		c.cfg.WSFailuresBeforePoll = 3
	}
	if c.cfg.WSRetryAfter <= 0 {
		c.cfg.WSRetryAfter = 5 * time.Minute
	}
	if c.cfg.PollWait <= 0 {
		c.cfg.PollWait = 25 * time.Second
	}
	return c, nil
}

// GroupHex returns the group id as hex.
func (c *Client) GroupHex() string { return c.gid }

// APIError is a non-2xx relay response.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("relay: %d %s", e.Status, e.Message) }

// IsStatus reports whether err is an APIError with the given HTTP status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

func apiError(resp *http.Response) error {
	defer resp.Body.Close()
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = json.Unmarshal(b, &e)
	if e.Error == "" {
		e.Error = http.StatusText(resp.StatusCode)
	}
	return &APIError{Status: resp.StatusCode, Message: e.Error}
}

func (c *Client) url(path string) string { return c.base.String() + path }

// send performs one request. body may be nil. When authed, a bearer token is
// attached and a 401 triggers one re-authentication and retry.
func (c *Client) send(ctx context.Context, method, path string, body []byte, hdr http.Header, authed bool) (*http.Response, error) {
	var stale string
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), rd)
		if err != nil {
			return nil, err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		var tok string
		if authed {
			if tok, err = c.ensureToken(ctx, stale); err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, err
		}
		if authed && resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = resp.Body.Close()
			stale = tok
			continue
		}
		return resp, nil
	}
}

// doJSON sends an optional JSON body, expects 2xx and decodes the JSON reply
// into out (if non-nil). Control calls are bounded by a 30s timeout.
func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, hdr http.Header, authed bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
		if hdr == nil {
			hdr = http.Header{}
		}
		hdr.Set("Content-Type", "application/json")
	}
	resp, err := c.send(ctx, method, path, body, hdr, authed)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// ---- auth ----------------------------------------------------------------

// Authenticate performs the challenge-response and stores a fresh token.
func (c *Client) Authenticate(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	_, err := c.authenticateLocked(ctx)
	return err
}

func (c *Client) authenticateLocked(ctx context.Context) (string, error) {
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if err := c.doJSON(ctx, "POST", "/v1/auth/challenge", map[string]string{"group_id": c.gid}, &ch, nil, false); err != nil {
		return "", err
	}
	nonce, err := base64Std(ch.Nonce)
	if err != nil {
		return "", errors.New("client: bad nonce from relay")
	}
	sig := ed25519.Sign(c.cfg.Identity.Ed25519, relay.AuthMessage(nonce, c.cfg.GroupID))
	var tr struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	err = c.doJSON(ctx, "POST", "/v1/auth/token", map[string]any{
		"group_id": c.gid, "pub": []byte(c.pub), "nonce": ch.Nonce, "sig": sig}, &tr, nil, false)
	if err != nil {
		return "", err
	}
	c.tokMu.Lock()
	c.token = tr.Token
	// Refresh 30s early so a request never races the expiry.
	c.tokExp = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - 30*time.Second)
	c.tokMu.Unlock()
	return tr.Token, nil
}

// ensureToken returns a valid token, authenticating if none, expired, or equal
// to stale (a token the relay just rejected).
func (c *Client) ensureToken(ctx context.Context, stale string) (string, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	c.tokMu.Lock()
	tok, exp := c.token, c.tokExp
	c.tokMu.Unlock()
	if tok != "" && tok != stale && time.Now().Before(exp) {
		return tok, nil
	}
	return c.authenticateLocked(ctx)
}

func (c *Client) invalidate(tok string) {
	c.tokMu.Lock()
	if c.token == tok {
		c.token = ""
	}
	c.tokMu.Unlock()
}

// ---- groups / roster -----------------------------------------------------

// CreateGroup registers the group on the relay with the genesis roster (sealed
// to its members) using the relay's enrollment token.
func (c *Client) CreateGroup(ctx context.Context, enrollToken string, genesis *roster.Roster) error {
	if genesis.GroupID != c.cfg.GroupID {
		return errors.New("client: genesis roster belongs to another group")
	}
	blob, err := genesis.Seal()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(c.cfg.Identity.Ed25519, relay.GroupCreateMessage(c.cfg.GroupID, c.pub, blob, genesis.Version))
	h := http.Header{}
	h.Set("X-ECB-Enroll", enrollToken)
	return c.doJSON(ctx, "POST", "/v1/groups", map[string]any{
		"group_id": c.gid, "ed25519_pub": []byte(c.pub), "roster_blob": blob,
		"roster_version": genesis.Version, "sig": sig}, nil, h, false)
}

// PublishRoster seals r to its members and publishes it, replacing the relay's
// allowed key set with r's Ed25519 keys (removal takes effect immediately).
// The caller must be a member of the relay's CURRENT key set and r.Version must
// exceed the relay's version.
func (c *Client) PublishRoster(ctx context.Context, r *roster.Roster) error {
	blob, err := r.Seal()
	if err != nil {
		return err
	}
	keys := make([]ed25519.PublicKey, len(r.Entries))
	raw := make([][]byte, len(r.Entries))
	for i, e := range r.Entries {
		keys[i] = e.Ed25519
		raw[i] = e.Ed25519
	}
	sig := ed25519.Sign(c.cfg.Identity.Ed25519, relay.RosterPubMessage(c.cfg.GroupID, r.Version, blob, keys))
	return c.doJSON(ctx, "POST", "/v1/groups/"+c.gid+"/roster", map[string]any{
		"version": r.Version, "blob": blob, "keys": raw, "sig": sig, "signer": []byte(c.pub)}, nil, nil, true)
}

// RosterInfo is a fetched roster. The caller must still Verify it against the
// roster it holds before trusting it.
type RosterInfo struct {
	Roster  *roster.Roster
	Blob    []byte // sealed blob as stored on the relay
	Version uint64 // relay-side version
}

// FetchRoster downloads and decrypts the roster blob.
func (c *Client) FetchRoster(ctx context.Context) (*RosterInfo, error) {
	var out struct {
		Version uint64 `json:"version"`
		Blob    []byte `json:"blob"`
	}
	if err := c.doJSON(ctx, "GET", "/v1/groups/"+c.gid+"/roster", nil, &out, nil, true); err != nil {
		return nil, err
	}
	r, err := roster.Open(out.Blob, c.cfg.Identity.X25519)
	if err != nil {
		return nil, fmt.Errorf("client: open roster: %w", err)
	}
	return &RosterInfo{Roster: r, Blob: out.Blob, Version: out.Version}, nil
}
