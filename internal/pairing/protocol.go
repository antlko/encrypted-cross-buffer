package pairing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

// MailboxAPI is the subset of the relay's mailbox API that pairing needs
// (satisfied by *client.Mailbox). Tests inject a malicious implementation.
type MailboxAPI interface {
	Post(ctx context.Context, id int, to string, data []byte) error
	Get(ctx context.Context, id int, party string, wait time.Duration) (data []byte, ok bool, err error)
	Burn(ctx context.Context, id int) error
}

// DefaultTimeout is the whole-pairing deadline (the relay's mailbox TTL).
const DefaultTimeout = 5 * time.Minute

const (
	labelDesc   = "ecb-desc-v1"
	labelRoster = "ecb-roster-v1"
	labelDone   = "ecb-done-v1"
)

type link struct {
	mb       MailboxAPI
	id       int
	me, peer string
	deadline time.Time
	pollWait time.Duration
}

func newLink(mb MailboxAPI, id int, me, peer string, timeout, pollWait time.Duration) *link {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if pollWait <= 0 {
		pollWait = 20 * time.Second
	}
	return &link{mb: mb, id: id, me: me, peer: peer, deadline: time.Now().Add(timeout), pollWait: pollWait}
}

func (l *link) send(ctx context.Context, data []byte) error {
	if len(data) > maxMsg {
		return fmt.Errorf("pairing: message too large (%d bytes)", len(data))
	}
	return l.mb.Post(ctx, l.id, l.peer, data)
}

func (l *link) recv(ctx context.Context) ([]byte, error) {
	for {
		remaining := time.Until(l.deadline)
		if remaining <= 0 {
			return nil, ErrTimeout
		}
		data, ok, err := l.mb.Get(ctx, l.id, l.me, min(l.pollWait, remaining))
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, ErrTimeout
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("pairing: mailbox: %w", err)
		}
		if ok {
			if len(data) > maxMsg {
				return nil, ErrBadMessage
			}
			return data, nil
		}
	}
}

// burn destroys the mailbox with a fresh context so it works after ctx ended.
func (l *link) burn() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = l.mb.Burn(ctx, l.id)
}

// descriptor is what the joiner tells the inviter about itself.
type descriptor struct {
	Name      string `json:"name"`
	Recipient string `json:"age"`
	Ed25519   []byte `json:"ed25519"`
}

// nameKey is the comparison key for device names: case-folded, with spaces and
// combining marks removed, so "Laptop", "laptop", "L a p t o p" and a name
// using a decomposed accent collide. It is dependency-free, so it is not full
// Unicode NFC normalisation (a precomposed letter is not decomposed); the
// roster's own byte-wise check still applies on top.
func nameKey(name string) string {
	var b strings.Builder
	for _, c := range name {
		if unicode.IsSpace(c) || unicode.In(c, unicode.Mn, unicode.Me, unicode.Mc) {
			continue
		}
		m := c
		for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		b.WriteRune(m)
	}
	return b.String()
}

func validateDescriptor(d descriptor, r *roster.Roster) error {
	name := d.Name
	if name == "" || len(name) > roster.MaxNameLen || utf8.RuneCountInString(name) > 64 || !utf8.ValidString(name) {
		return fmt.Errorf("%w: device name must be 1-%d characters", ErrRejected, roster.MaxNameLen)
	}
	for _, c := range name {
		if !unicode.IsPrint(c) || unicode.In(c, unicode.Cf, unicode.Cs, unicode.Co) {
			return fmt.Errorf("%w: device name has non-printable, invisible or private-use characters", ErrRejected)
		}
	}
	key := nameKey(name)
	if key == "" {
		return fmt.Errorf("%w: device name must contain visible characters", ErrRejected)
	}
	if len(d.Ed25519) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad signing key length", ErrRejected)
	}
	if _, err := age.ParseX25519Recipient(d.Recipient); err != nil {
		return fmt.Errorf("%w: bad age recipient", ErrRejected)
	}
	if len(r.Entries) >= roster.MaxDevices {
		return fmt.Errorf("%w: the group already has %d devices", ErrRejected, roster.MaxDevices)
	}
	id := roster.DeviceID(d.Ed25519)
	for _, e := range r.Entries {
		if e.DeviceID == id || bytes.Equal(e.Ed25519, d.Ed25519) || e.X25519Pub == d.Recipient {
			return fmt.Errorf("%w: device is already in the group", ErrRejected)
		}
		if e.Name == name || nameKey(e.Name) == key {
			return fmt.Errorf("%w: a device named %q already exists; pick another --name", ErrRejected, name)
		}
	}
	return nil
}

// ---- inviter (existing device, role 0, mailbox party "a") ------------------

// Inviter is the existing device that admits a new one.
type Inviter struct {
	MB       MailboxAPI
	Self     *keystore.Identity
	Roster   *roster.Roster // current verified roster; Self must be a member
	RelayURL string
	// Publish publishes the new signed roster (the relay then admits the
	// joiner's key) and persists it locally. Called only after mutual key
	// confirmation and descriptor validation.
	Publish func(ctx context.Context, r *roster.Roster) error
	Now     func() time.Time
	// Timeout bounds the whole pairing (default DefaultTimeout); PollWait is the
	// mailbox long-poll length (default 20s).
	Timeout, PollWait time.Duration
}

// InviteResult is the outcome of a successful invitation.
type InviteResult struct {
	Roster *roster.Roster
	Added  roster.Entry
}

// Run performs one pairing attempt on the mailbox named in code. On any error
// or timeout the mailbox is burned immediately (one attempt per mailbox).
func (in *Inviter) Run(ctx context.Context, code Code) (res *InviteResult, err error) {
	l := newLink(in.MB, code.Mailbox, "a", "b", in.Timeout, in.PollWait)
	defer l.burn() // success: after "done"; failure: at once
	ctx, cancel := context.WithDeadline(ctx, l.deadline)
	defer cancel()
	now := in.Now
	if now == nil {
		now = time.Now
	}
	selfID := in.Self.DeviceID()
	if _, ok := in.Roster.Lookup(selfID); !ok {
		return nil, errors.New("pairing: this device is not in its roster")
	}

	ps, err := newPake(code, roleA)
	if err != nil {
		return nil, err
	}
	msg1 := ps.bytes()
	if err := l.send(ctx, msg1); err != nil {
		return nil, err
	}
	msg2, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	if err := ps.update(msg2); err != nil {
		return nil, err
	}
	k, err := ps.key()
	if err != nil {
		return nil, err
	}
	ks, err := deriveKeys(k)
	if err != nil {
		return nil, err
	}
	tr := transcript(msg1, msg2)

	if err := l.send(ctx, confirmMAC(ks, "A", tr)); err != nil {
		return nil, err
	}
	confB, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	// Mutual confirmation: nothing is published unless this passes.
	if err := checkMAC(ks, "B", tr, confB); err != nil {
		return nil, err
	}

	raw, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := open(ks, labelDesc, code.Mailbox, raw)
	if err != nil {
		return nil, err
	}
	var d descriptor
	if err := json.Unmarshal(pt, &d); err != nil {
		return nil, fmt.Errorf("%w: descriptor", ErrBadMessage)
	}
	if err := validateDescriptor(d, in.Roster); err != nil {
		return nil, err
	}
	entry := roster.NewEntry(d.Name, d.Recipient, ed25519.PublicKey(d.Ed25519), now().UnixMilli())
	next, err := in.Roster.Add(selfID, entry)
	if err != nil {
		return nil, err
	}
	if err := next.Sign(in.Self.Ed25519); err != nil {
		return nil, err
	}
	rb, err := next.Marshal()
	if err != nil {
		return nil, err
	}
	// Build and size-check the reply BEFORE publishing so an oversized roster
	// cannot leave the joiner admitted but without its roster.
	var m bytes.Buffer
	m.Write(next.GroupID[:])
	_ = binary.Write(&m, binary.BigEndian, uint16(len(in.RelayURL)))
	m.WriteString(in.RelayURL)
	m.Write(rb)
	sealed, err := seal(ks, labelRoster, code.Mailbox, m.Bytes())
	if err != nil {
		return nil, err
	}
	if len(sealed) > maxMsg {
		return nil, fmt.Errorf("%w: roster too large for the pairing channel", ErrRejected)
	}
	if err := in.Publish(ctx, next); err != nil {
		return nil, fmt.Errorf("pairing: publish roster: %w", err)
	}
	entry, _ = next.Lookup(entry.DeviceID)
	if err := l.send(ctx, sealed); err != nil {
		return nil, fmt.Errorf("pairing: the roster was published but the new device did not receive it (remove it with `ecb devices rm %s` and retry): %w", d.Name, err)
	}
	doneRaw, err := l.recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("pairing: no confirmation from the new device (it was added; check `ecb devices` and its status): %w", err)
	}
	done, err := open(ks, labelDone, code.Mailbox, doneRaw)
	if err != nil || string(done) != "done" {
		return nil, fmt.Errorf("%w: bad completion message", ErrBadMessage)
	}
	return &InviteResult{Roster: next, Added: entry}, nil
}

// ---- joiner (new device, role 1, mailbox party "b") -------------------------

// Joiner is the new device.
type Joiner struct {
	MB   MailboxAPI
	Self *keystore.Identity
	Name string
	// Finish is called with the verified roster before the inviter is told we
	// are done. It must persist the state and prove relay access (authenticate).
	Finish            func(ctx context.Context, r *Joined) error
	Timeout, PollWait time.Duration
}

// Joined is what the joiner learns from the inviter.
type Joined struct {
	GroupID  [16]byte
	RelayURL string // as announced by the inviter (informational)
	Roster   *roster.Roster
}

// Run performs one join attempt. The mailbox is burned on failure; on success
// the inviter burns it after receiving "done" (burning earlier could drop it).
func (j *Joiner) Run(ctx context.Context, code Code) (res *Joined, err error) {
	l := newLink(j.MB, code.Mailbox, "b", "a", j.Timeout, j.PollWait)
	ok := false
	defer func() {
		if !ok {
			l.burn()
		}
	}()
	ctx, cancel := context.WithDeadline(ctx, l.deadline)
	defer cancel()

	ps, err := newPake(code, roleB)
	if err != nil {
		return nil, err
	}
	msg1, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	if err := ps.update(msg1); err != nil {
		return nil, err
	}
	msg2 := ps.bytes()
	if err := l.send(ctx, msg2); err != nil {
		return nil, err
	}
	k, err := ps.key()
	if err != nil {
		return nil, err
	}
	ks, err := deriveKeys(k)
	if err != nil {
		return nil, err
	}
	tr := transcript(msg1, msg2)

	confA, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	if err := checkMAC(ks, "A", tr, confA); err != nil {
		return nil, err
	}
	if err := l.send(ctx, confirmMAC(ks, "B", tr)); err != nil {
		return nil, err
	}

	// Only now, after mutual confirmation, do we reveal our descriptor.
	d, _ := json.Marshal(descriptor{Name: j.Name, Recipient: j.Self.Recipient(), Ed25519: j.Self.PublicKey()})
	sealedDesc, err := seal(ks, labelDesc, code.Mailbox, d)
	if err != nil {
		return nil, err
	}
	if err := l.send(ctx, sealedDesc); err != nil {
		return nil, err
	}

	raw, err := l.recv(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := open(ks, labelRoster, code.Mailbox, raw)
	if err != nil {
		return nil, err
	}
	joined, err := j.parseRoster(pt)
	if err != nil {
		return nil, err
	}
	if j.Finish != nil {
		if err := j.Finish(ctx, joined); err != nil {
			return nil, err
		}
	}
	done, err := seal(ks, labelDone, code.Mailbox, []byte("done"))
	if err != nil {
		return nil, err
	}
	if err := l.send(ctx, done); err != nil {
		return nil, err
	}
	ok = true
	return joined, nil
}

func (j *Joiner) parseRoster(pt []byte) (*Joined, error) {
	if len(pt) < 18 {
		return nil, ErrBadMessage
	}
	var gid [16]byte
	copy(gid[:], pt[:16])
	ul := int(binary.BigEndian.Uint16(pt[16:18]))
	if len(pt) < 18+ul {
		return nil, ErrBadMessage
	}
	url := string(pt[18 : 18+ul])
	r, err := roster.Unmarshal(pt[18+ul:])
	if err != nil {
		return nil, fmt.Errorf("%w: roster: %v", ErrRejected, err)
	}
	if err := verifyBootstrapRoster(r); err != nil {
		return nil, err
	}
	if r.GroupID != gid {
		return nil, fmt.Errorf("%w: group id mismatch", ErrRejected)
	}
	me, ok := r.Lookup(j.Self.DeviceID())
	if !ok || me.Name != j.Name || me.X25519Pub != j.Self.Recipient() || !bytes.Equal(me.Ed25519, j.Self.PublicKey()) {
		return nil, fmt.Errorf("%w: roster does not contain this device as announced", ErrRejected)
	}
	return &Joined{GroupID: gid, RelayURL: url, Roster: r}, nil
}
