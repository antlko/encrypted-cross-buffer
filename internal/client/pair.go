package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mailbox is the unauthenticated pairing-mailbox API (the joining device has
// no credentials yet). The relay never interprets messages; parties are "a"
// (the existing device) and "b" (the joiner).
type Mailbox struct {
	base string
	hc   *http.Client
}

// NewMailbox creates a Mailbox client; hc may be nil for the default.
func NewMailbox(baseURL string, hc *http.Client) (*Mailbox, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("client: BaseURL must be an http(s) URL")
	}
	if hc == nil {
		hc = NewHTTPClient()
	}
	return &Mailbox{base: u.String(), hc: hc}, nil
}

// Mailbox returns an unauthenticated mailbox client sharing this client's transport.
func (c *Client) Mailbox() *Mailbox { return &Mailbox{base: c.base.String(), hc: c.hc} }

// PairCreate opens a mailbox for this group (authenticated). It returns its
// number (1..99) and lifetime.
func (c *Client) PairCreate(ctx context.Context) (id int, expiresIn time.Duration, err error) {
	var out struct {
		Mailbox   int `json:"mailbox"`
		ExpiresIn int `json:"expires_in"`
	}
	if err = c.doJSON(ctx, "POST", "/v1/pair", nil, &out, nil, true); err != nil {
		return 0, 0, err
	}
	return out.Mailbox, time.Duration(out.ExpiresIn) * time.Second, nil
}

func (m *Mailbox) req(ctx context.Context, method, path, ctype string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, rd)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	return m.hc.Do(req)
}

// Post sends data (<=16 KiB) to party "a" or "b" of mailbox id.
func (m *Mailbox) Post(ctx context.Context, id int, to string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := jsonBytes(map[string]any{"to": to, "data": data})
	if err != nil {
		return err
	}
	resp, err := m.req(ctx, "POST", fmt.Sprintf("/v1/pair/%d/msg", id), "application/json", body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	return resp.Body.Close()
}

// Get waits up to wait (relay caps at 25s) for the next message for party. ok
// is false on timeout. A burned/expired mailbox yields an APIError with status 404.
func (m *Mailbox) Get(ctx context.Context, id int, party string, wait time.Duration) (data []byte, ok bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, wait+30*time.Second)
	defer cancel()
	resp, err := m.req(ctx, "GET", fmt.Sprintf("/v1/pair/%d/msg?for=%s&wait=%d", id, url.QueryEscape(party), int(wait/time.Second)), "", nil)
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, apiError(resp)
	}
	defer resp.Body.Close()
	var out struct {
		Data []byte `json:"data"`
	}
	if err := decodeJSON(resp.Body, &out); err != nil {
		return nil, false, err
	}
	return out.Data, true, nil
}

// Burn destroys the mailbox (idempotent). Both sides call it on failure.
func (m *Mailbox) Burn(ctx context.Context, id int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := m.req(ctx, "DELETE", fmt.Sprintf("/v1/pair/%d", id), "", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp)
	}
	return resp.Body.Close()
}
