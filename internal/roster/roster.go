// Package roster implements the signed device roster of a sync group.
//
// A roster lists every device of a group (its keys) and carries a monotonic
// version and an Ed25519 signature by one device that was a member of the
// PREVIOUS roster (a removed device therefore cannot sign the next version).
//
// Canonical binary encoding (big-endian, deterministic; JSON is never signed):
//
//	"ECBR"(4) | fmt u8=1 | group_id[16] | version u64 | signer[16] | n u16 |
//	n * entry | sig[64]
//	entry = device_id[16] | name_len u8 | name | x25519_len u8 | x25519 (age
//	        recipient string, ASCII) | ed25519_pk[32] | added_by[16] | added_at_ms i64
//
// Entries are sorted by strictly increasing device_id. The signature covers
// "ecb-roster-v1" || (all bytes preceding sig).
//
// Trust caveats:
//   - Genesis (Verify with held == nil) is trust-on-first-use: a self-signed
//     single-member roster proves nothing about who the member is. It is only
//     safe if the roster arrives through the authenticated pairing channel
//     (PAKE + key confirmation), never from the relay.
//   - A holder with a stale roster accepts a newer roster signed by a member
//     that has since been removed (it is still a member of the held roster).
//     Closing that window needs relay-side enforcement of the current roster.
//   - Entries retained between versions are immutable (see Verify).
package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"

	"filippo.io/age"

	"github.com/antlko/encrypted-cross-buffer/internal/frame"
)

const (
	// MaxDevices is the maximum number of devices in a group.
	MaxDevices = 64
	// MaxNameLen is the maximum device name length in bytes.
	MaxNameLen = 64
	// MaxBlobSize bounds a marshalled roster / sealed roster blob.
	MaxBlobSize = 1 << 20

	sigContext = "ecb-roster-v1"
	blobMagic  = "ECBR"
	blobFormat = 1
)

// Errors. Use errors.Is.
var (
	ErrInvalid       = errors.New("roster: invalid roster")
	ErrBadSignature  = errors.New("roster: bad signature")
	ErrRollback      = errors.New("roster: version not newer than held roster")
	ErrSignerNotHeld = errors.New("roster: signer is not a member of the held roster")
	ErrGroupMismatch = errors.New("roster: group id differs from held roster")
	ErrNeedGenesis   = errors.New("roster: no held roster and version is not 1")
)

// DeviceID returns SHA-256(pk)[:16].
func DeviceID(pk ed25519.PublicKey) [16]byte {
	s := sha256.Sum256(pk)
	var id [16]byte
	copy(id[:], s[:16])
	return id
}

// Entry describes one device.
type Entry struct {
	DeviceID  [16]byte
	Name      string
	X25519Pub string // age recipient string ("age1...")
	Ed25519   ed25519.PublicKey
	AddedBy   [16]byte
	AddedAtMs int64
}

// NewEntry builds an Entry with a derived DeviceID. AddedBy is set by NewGenesis/Add.
func NewEntry(name, x25519Recipient string, edPub ed25519.PublicKey, addedAtMs int64) Entry {
	return Entry{DeviceID: DeviceID(edPub), Name: name, X25519Pub: x25519Recipient, Ed25519: edPub, AddedAtMs: addedAtMs}
}

// Recipient parses the entry's age recipient.
func (e Entry) Recipient() (*age.X25519Recipient, error) {
	return age.ParseX25519Recipient(e.X25519Pub)
}

func (e Entry) validate() error {
	if len(e.Ed25519) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad ed25519 key length", ErrInvalid)
	}
	if DeviceID(e.Ed25519) != e.DeviceID {
		return fmt.Errorf("%w: device id does not match key", ErrInvalid)
	}
	if len(e.Name) == 0 || len(e.Name) > MaxNameLen || !utf8.ValidString(e.Name) {
		return fmt.Errorf("%w: bad device name", ErrInvalid)
	}
	r, err := age.ParseX25519Recipient(e.X25519Pub)
	if err != nil || r.String() != e.X25519Pub {
		return fmt.Errorf("%w: bad x25519 recipient", ErrInvalid)
	}
	return nil
}

// Roster is a (possibly unsigned) device roster.
type Roster struct {
	GroupID [16]byte
	Version uint64
	Entries []Entry
	Signer  [16]byte
	Sig     []byte
}

// NewGenesis creates and signs version 1 containing only self (signed by its own key).
func NewGenesis(groupID [16]byte, self Entry, sk ed25519.PrivateKey) (*Roster, error) {
	self.AddedBy = self.DeviceID
	r := &Roster{GroupID: groupID, Version: 1, Entries: []Entry{self}}
	if err := r.Sign(sk); err != nil {
		return nil, err
	}
	return r, nil
}

// Add returns an UNSIGNED copy with version+1 that also contains e, recorded as
// added by adder. Call Sign on the result.
func (r *Roster) Add(adder [16]byte, e Entry) (*Roster, error) {
	if _, ok := r.Lookup(e.DeviceID); ok {
		return nil, fmt.Errorf("%w: duplicate device", ErrInvalid)
	}
	e.AddedBy = adder
	n := r.next()
	n.Entries = append(n.Entries, e)
	sortEntries(n.Entries)
	if err := n.validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// Remove returns an UNSIGNED copy with version+1 without device id.
func (r *Roster) Remove(id [16]byte) (*Roster, error) {
	n := r.next()
	n.Entries = n.Entries[:0]
	found := false
	for _, e := range r.Entries {
		if e.DeviceID == id {
			found = true
			continue
		}
		n.Entries = append(n.Entries, e)
	}
	if !found {
		return nil, fmt.Errorf("%w: device not in roster", ErrInvalid)
	}
	if err := n.validate(); err != nil {
		return nil, err
	}
	return n, nil
}

func (r *Roster) next() *Roster {
	n := &Roster{GroupID: r.GroupID, Version: r.Version + 1}
	n.Entries = append([]Entry(nil), r.Entries...)
	return n
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool { return bytes.Compare(es[i].DeviceID[:], es[j].DeviceID[:]) < 0 })
}

// Lookup returns the entry for a device id.
func (r *Roster) Lookup(id [16]byte) (Entry, bool) {
	for _, e := range r.Entries {
		if e.DeviceID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// KeyLookup adapts the roster to frame.KeyLookup (sender signature keys).
func (r *Roster) KeyLookup() frame.KeyLookup {
	return func(id [16]byte) (ed25519.PublicKey, bool) {
		e, ok := r.Lookup(id)
		return e.Ed25519, ok
	}
}

// Recipients returns age recipients for all devices.
func (r *Roster) Recipients() ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(r.Entries))
	for _, e := range r.Entries {
		rc, err := e.Recipient()
		if err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, nil
}

// validate checks structure (not the signature).
func (r *Roster) validate() error {
	if r.Version == 0 {
		return fmt.Errorf("%w: version 0", ErrInvalid)
	}
	if len(r.Entries) == 0 {
		return fmt.Errorf("%w: empty roster", ErrInvalid)
	}
	if len(r.Entries) > MaxDevices {
		return fmt.Errorf("%w: more than %d devices", ErrInvalid, MaxDevices)
	}
	for i, e := range r.Entries {
		if err := e.validate(); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(r.Entries[i-1].DeviceID[:], e.DeviceID[:]) >= 0 {
			return fmt.Errorf("%w: duplicate or unsorted device ids", ErrInvalid)
		}
	}
	return nil
}

// body returns the canonical encoding without the signature.
func (r *Roster) body() ([]byte, error) {
	es := append([]Entry(nil), r.Entries...)
	sortEntries(es)
	var b bytes.Buffer
	b.WriteString(blobMagic)
	b.WriteByte(blobFormat)
	b.Write(r.GroupID[:])
	_ = binary.Write(&b, binary.BigEndian, r.Version)
	b.Write(r.Signer[:])
	_ = binary.Write(&b, binary.BigEndian, uint16(len(es)))
	for _, e := range es {
		b.Write(e.DeviceID[:])
		b.WriteByte(byte(len(e.Name)))
		b.WriteString(e.Name)
		b.WriteByte(byte(len(e.X25519Pub)))
		b.WriteString(e.X25519Pub)
		b.Write(e.Ed25519)
		b.Write(e.AddedBy[:])
		_ = binary.Write(&b, binary.BigEndian, e.AddedAtMs)
	}
	return b.Bytes(), nil
}

func signedBytes(body []byte) []byte { return append([]byte(sigContext), body...) }

// Sign sets Signer to the id of sk and signs the roster. It fails if the
// roster is structurally invalid.
func (r *Roster) Sign(sk ed25519.PrivateKey) error {
	if len(sk) != ed25519.PrivateKeySize {
		return errors.New("roster: invalid signing key")
	}
	sortEntries(r.Entries)
	if err := r.validate(); err != nil {
		return err
	}
	r.Signer = DeviceID(sk.Public().(ed25519.PublicKey))
	body, _ := r.body()
	r.Sig = ed25519.Sign(sk, signedBytes(body))
	return nil
}

// Verify checks r against the roster the caller currently holds (nil if none).
// With held == nil, r must be a valid genesis (version 1, one member, self-signed).
// Otherwise r.Version must be > held.Version, the group must match and the
// signer must be a member of held (so removed devices cannot sign), every
// device that is new relative to held must have been added by the signer, and
// every retained device must be field-for-field identical to its held entry.
func (r *Roster) Verify(held *Roster) error {
	if err := r.validate(); err != nil {
		return err
	}
	var signerKey ed25519.PublicKey
	if held == nil {
		if r.Version != 1 {
			return ErrNeedGenesis
		}
		if len(r.Entries) != 1 || r.Signer != r.Entries[0].DeviceID || r.Entries[0].AddedBy != r.Signer {
			return fmt.Errorf("%w: genesis must be a single self-signed member", ErrInvalid)
		}
		signerKey = r.Entries[0].Ed25519
	} else {
		if r.GroupID != held.GroupID {
			return ErrGroupMismatch
		}
		if r.Version <= held.Version {
			return ErrRollback
		}
		se, ok := held.Lookup(r.Signer)
		if !ok {
			return ErrSignerNotHeld
		}
		signerKey = se.Ed25519
		for _, e := range r.Entries {
			old, ok := held.Lookup(e.DeviceID)
			if !ok {
				if e.AddedBy != r.Signer {
					return fmt.Errorf("%w: new device not added by signer", ErrInvalid)
				}
				continue
			}
			// Retained entries are immutable between versions.
			if old.Name != e.Name || old.X25519Pub != e.X25519Pub || !bytes.Equal(old.Ed25519, e.Ed25519) ||
				old.AddedBy != e.AddedBy || old.AddedAtMs != e.AddedAtMs {
				return fmt.Errorf("%w: retained device %x was modified", ErrInvalid, e.DeviceID[:4])
			}
		}
	}
	body, _ := r.body()
	if len(r.Sig) != ed25519.SignatureSize || !ed25519.Verify(signerKey, signedBytes(body), r.Sig) {
		return ErrBadSignature
	}
	return nil
}

// Marshal returns the canonical encoding including the signature.
func (r *Roster) Marshal() ([]byte, error) {
	if len(r.Sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: unsigned", ErrInvalid)
	}
	b, _ := r.body()
	return append(b, r.Sig...), nil
}

// Unmarshal strictly parses a canonical roster. It does NOT verify the signature.
func Unmarshal(data []byte) (*Roster, error) {
	if len(data) > MaxBlobSize {
		return nil, fmt.Errorf("%w: too large", ErrInvalid)
	}
	rd := bytes.NewReader(data)
	bad := func(what string) (*Roster, error) { return nil, fmt.Errorf("%w: %s", ErrInvalid, what) }
	read := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(rd, b); err != nil {
			return nil
		}
		return b
	}
	if string(read(4)) != blobMagic {
		return bad("magic")
	}
	if f := read(1); f == nil || f[0] != blobFormat {
		return bad("format")
	}
	r := &Roster{}
	g, v, s, n := read(16), read(8), read(16), read(2)
	if g == nil || v == nil || s == nil || n == nil {
		return bad("truncated header")
	}
	copy(r.GroupID[:], g)
	r.Version = binary.BigEndian.Uint64(v)
	copy(r.Signer[:], s)
	count := int(binary.BigEndian.Uint16(n))
	if count == 0 || count > MaxDevices {
		return bad("device count")
	}
	for i := 0; i < count; i++ {
		var e Entry
		id, nl := read(16), read(1)
		if id == nil || nl == nil {
			return bad("truncated entry")
		}
		copy(e.DeviceID[:], id)
		name := read(int(nl[0]))
		xl := read(1)
		if (name == nil && nl[0] != 0) || xl == nil {
			return bad("truncated entry")
		}
		x := read(int(xl[0]))
		ed, ab, at := read(ed25519.PublicKeySize), read(16), read(8)
		if x == nil || ed == nil || ab == nil || at == nil {
			return bad("truncated entry")
		}
		e.Name, e.X25519Pub = string(name), string(x)
		e.Ed25519 = ed25519.PublicKey(ed)
		copy(e.AddedBy[:], ab)
		e.AddedAtMs = int64(binary.BigEndian.Uint64(at))
		r.Entries = append(r.Entries, e)
	}
	r.Sig = read(ed25519.SignatureSize)
	if r.Sig == nil {
		return bad("truncated signature")
	}
	if rd.Len() != 0 {
		return bad("trailing data")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Seal marshals the roster and age-encrypts it to all its members, producing an
// opaque blob suitable for the (untrusted) relay.
func (r *Roster) Seal() ([]byte, error) {
	m, err := r.Marshal()
	if err != nil {
		return nil, err
	}
	rcpts, err := r.Recipients()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rcpts...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(m); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Open decrypts a sealed roster blob and parses it. The caller must still call
// Verify against the roster it holds.
func Open(blob []byte, id age.Identity) (*Roster, error) {
	if len(blob) > 2*MaxBlobSize {
		return nil, fmt.Errorf("%w: blob too large", ErrInvalid)
	}
	rd, err := age.Decrypt(bytes.NewReader(blob), id)
	if err != nil {
		return nil, fmt.Errorf("roster: decrypt: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(rd, MaxBlobSize+1))
	if err != nil {
		return nil, fmt.Errorf("roster: decrypt: %w", err)
	}
	return Unmarshal(data)
}
