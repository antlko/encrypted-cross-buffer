package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"filippo.io/age"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/envelope"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
)

// ErrNoRecipients means the roster has no device other than this one.
var ErrNoRecipients = errors.New("client: roster has no other devices")

// ItemRef identifies an uploaded item.
type ItemRef struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

// saveState persists ONLY the replay/send counters. The roster is owned by
// whoever publishes it (daemon refresh, CLI pair/devices rm): this client's
// in-memory copy may be stale and must never be written back.
func (c *Client) saveState() error {
	if c.cfg.Store == nil || c.cfg.State == nil {
		return nil
	}
	mem := c.cfg.State
	return c.cfg.Store.UpdateState(func(cur *keystore.State) error {
		if cur.GroupID == ([16]byte{}) { // nothing stored yet: bootstrap
			cur.RelayURL, cur.GroupID = mem.RelayURL, mem.GroupID
			cur.RosterBlob, cur.RosterVersion = mem.RosterBlob, mem.RosterVersion
		}
		if cur.SendCounter < mem.SendCounter {
			cur.SendCounter = mem.SendCounter
		}
		for k, v := range mem.LastCounters {
			if cur.LastCounters == nil {
				cur.LastCounters = map[string]uint64{}
			}
			if cur.LastCounters[k] < v {
				cur.LastCounters[k] = v
			}
		}
		return nil
	})
}

// SendItem seals body for every OTHER device of the current roster and uploads
// it. The frame is sealed in memory (the relay requires Content-Length) and
// sent as a fixed-length body; the send counter is persisted BEFORE the upload
// so a counter is never reused.
func (c *Client) SendItem(ctx context.Context, ctype uint8, body []byte) (ItemRef, error) {
	if c.cfg.State == nil || c.cfg.Roster == nil {
		return ItemRef{}, errors.New("client: State and Roster are required to send")
	}
	r, err := c.cfg.Roster.Roster()
	if err != nil {
		return ItemRef{}, err
	}
	self := c.cfg.Identity.DeviceID()
	var rcpts []age.Recipient
	for _, e := range r.Entries {
		if e.DeviceID == self {
			continue
		}
		rc, err := e.Recipient()
		if err != nil {
			return ItemRef{}, err
		}
		rcpts = append(rcpts, rc)
	}
	if len(rcpts) == 0 {
		return ItemRef{}, ErrNoRecipients
	}
	c.stMu.Lock()
	var ctr uint64
	if c.cfg.Store != nil {
		// Allocated under the cross-process lock so a CLI send and the daemon
		// can never reuse a counter; the roster is not touched.
		if ctr, err = c.cfg.Store.NextSendCounter(); err == nil {
			c.cfg.State.SendCounter = max(c.cfg.State.SendCounter, ctr)
		}
	} else {
		ctr = c.cfg.State.NextSendCounter()
	}
	c.stMu.Unlock()
	if err != nil {
		return ItemRef{}, fmt.Errorf("client: save state: %w", err)
	}
	frameBytes, err := envelope.SealBytes(envelope.SealParams{
		GroupID: c.cfg.GroupID, SenderID: self, SigningKey: c.cfg.Identity.Ed25519,
		Recipients: rcpts, Counter: ctr, Now: c.cfg.Now, Limits: c.cfg.Limits,
	}, ctype, body)
	if err != nil {
		return ItemRef{}, err
	}
	h := http.Header{"Content-Type": {"application/octet-stream"}}
	resp, err := c.send(ctx, "POST", "/v1/items", frameBytes, h, true)
	if err != nil {
		return ItemRef{}, err
	}
	if resp.StatusCode/100 != 2 {
		return ItemRef{}, apiError(resp)
	}
	defer resp.Body.Close()
	var ref ItemRef
	if err := decodeJSON(resp.Body, &ref); err != nil {
		return ItemRef{}, err
	}
	return ref, nil
}

// FetchItem downloads item id, verifies the sender signature and replay
// counter, decrypts it and only then records the sender's counter (and
// persists State).
func (c *Client) FetchItem(ctx context.Context, id string) (*envelope.Item, error) {
	if c.cfg.State == nil || c.cfg.Roster == nil {
		return nil, errors.New("client: State and Roster are required to fetch")
	}
	r, err := c.cfg.Roster.Roster()
	if err != nil {
		return nil, err
	}
	resp, err := c.send(ctx, "GET", "/v1/items/"+id, nil, nil, true)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	defer resp.Body.Close()
	item, err := envelope.Open(resp.Body, envelope.OpenParams{
		GroupID:  c.cfg.GroupID,
		Lookup:   r.KeyLookup(),
		Identity: c.cfg.Identity.X25519,
		LastCounter: func(sender [16]byte) uint64 {
			c.stMu.Lock()
			defer c.stMu.Unlock()
			return c.cfg.State.LastCounter(sender)
		},
		TTL: c.cfg.TTL, Now: c.cfg.Now, Limits: c.cfg.Limits,
	})
	if err != nil {
		return nil, err
	}
	c.stMu.Lock()
	defer c.stMu.Unlock()
	c.cfg.State.SetLastCounter(item.Header.SenderID, item.Header.Counter)
	if err := c.saveState(); err != nil {
		return nil, fmt.Errorf("client: save state: %w", err)
	}
	return item, nil
}
