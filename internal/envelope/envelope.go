// Package envelope seals and opens clipboard items.
//
// Sealing: inner plaintext (ctype | comp | raw_len | body) -> age (binary,
// N X25519 recipients) -> outer frame signed with the sender's Ed25519 key
// (see package frame).
//
// Opening verifies the sender signature (and replay/age checks on the header)
// BEFORE any decryption, then enforces size limits before and while
// decompressing.
//
// Inner plaintext layout (big-endian):
//
//	ctype u8 (1=text/utf-8, 2=image/png) | comp u8 (0=none, 1=zstd) | raw_len u64 | body
package envelope

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/antlko/encrypted-cross-buffer/internal/frame"
)

// Content types.
const (
	// CTypeText is UTF-8 text.
	CTypeText uint8 = 1
	// CTypeImagePNG is a PNG image, stored unchanged.
	CTypeImagePNG uint8 = 2
)

// Compression modes of the inner plaintext.
const (
	compNone uint8 = 0
	compZstd uint8 = 1
)

const innerHeaderSize = 10

// Default limits and timing.
const (
	DefaultMaxRaw   uint64 = 256 << 20
	DefaultMaxImage uint64 = 8 << 20
	DefaultTTL             = 10 * time.Minute
	// ClockSkew is both the extra age allowed on top of the TTL and the
	// tolerated distance into the future.
	ClockSkew = 5 * time.Minute
)

// Errors returned by Open and Seal. Use errors.Is.
var (
	ErrUnknownCType = errors.New("envelope: unknown content type")
	ErrBadInner     = errors.New("envelope: malformed inner plaintext")
	ErrTooBig       = errors.New("envelope: item exceeds size limit")
	ErrReplay       = errors.New("envelope: replayed or stale counter")
	ErrExpired      = errors.New("envelope: item too old")
	ErrFuture       = errors.New("envelope: item timestamp in the future")
	ErrWrongGroup   = errors.New("envelope: wrong group")
	ErrBadText      = errors.New("envelope: text is not valid UTF-8")
	ErrDecrypt      = errors.New("envelope: decryption failed")
)

// Limits are the size limits. Zero fields take defaults.
type Limits struct {
	// MaxRaw caps raw_len of any item (default 256 MiB).
	MaxRaw uint64
	// MaxImage caps raw_len of images (default 8 MiB).
	MaxImage uint64
	// MaxText caps raw_len of text (default MaxRaw).
	MaxText uint64
	// MaxCiphertext caps the frame ct_len (default frame.DefaultMaxCiphertext).
	MaxCiphertext uint64
}

func (l Limits) norm() Limits {
	if l.MaxRaw == 0 {
		l.MaxRaw = DefaultMaxRaw
	}
	if l.MaxImage == 0 {
		l.MaxImage = DefaultMaxImage
	}
	if l.MaxText == 0 {
		l.MaxText = l.MaxRaw
	}
	if l.MaxCiphertext == 0 {
		l.MaxCiphertext = frame.DefaultMaxCiphertext
	}
	return l
}

func (l Limits) forType(ct uint8) (uint64, error) {
	l = l.norm()
	switch ct {
	case CTypeText:
		return min(l.MaxText, l.MaxRaw), nil
	case CTypeImagePNG:
		return min(l.MaxImage, l.MaxRaw), nil
	}
	return 0, fmt.Errorf("%w: %d", ErrUnknownCType, ct)
}

// SealParams configure Seal.
type SealParams struct {
	GroupID    [16]byte
	SenderID   [16]byte
	SigningKey ed25519.PrivateKey
	// Recipients are all devices that must be able to read the item
	// (normally including the sender itself is NOT needed).
	Recipients []age.Recipient
	// Counter is the sender's monotonic counter value for this item (>= 1).
	Counter uint64
	// Now returns the current time; nil means time.Now.
	Now    func() time.Time
	Limits Limits
}

// Seal builds a signed, encrypted frame for body and writes it to dst. Text is
// zstd-compressed when that shrinks it; PNG is never compressed.
func Seal(dst io.Writer, p SealParams, ctype uint8, body []byte) error {
	if len(p.Recipients) == 0 {
		return errors.New("envelope: no recipients")
	}
	if p.Counter == 0 {
		return errors.New("envelope: counter must be >= 1")
	}
	lim, err := p.Limits.forType(ctype)
	if err != nil {
		return err
	}
	if uint64(len(body)) > lim {
		return fmt.Errorf("%w: %d > %d", ErrTooBig, len(body), lim)
	}
	if ctype == CTypeText && !utf8.Valid(body) {
		return ErrBadText
	}
	if ctype == CTypeImagePNG && !hasPNGSig(body) {
		return fmt.Errorf("%w: missing PNG signature", ErrBadInner)
	}
	comp, stored := compNone, body
	if ctype == CTypeText && len(body) > 0 {
		if c := encodeZstd(body); len(c) < len(body) {
			comp, stored = compZstd, c
		}
	}
	var ct bytes.Buffer
	aw, err := age.Encrypt(&ct, p.Recipients...)
	if err != nil {
		return err
	}
	var ih [innerHeaderSize]byte
	ih[0], ih[1] = ctype, comp
	putU64(ih[2:], uint64(len(body)))
	if _, err := aw.Write(ih[:]); err != nil {
		return err
	}
	if _, err := aw.Write(stored); err != nil {
		return err
	}
	if err := aw.Close(); err != nil {
		return err
	}
	if uint64(ct.Len()) > p.Limits.norm().MaxCiphertext {
		return fmt.Errorf("%w: ciphertext %d bytes", ErrTooBig, ct.Len())
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	h := frame.Header{
		GroupID: p.GroupID, SenderID: p.SenderID, Counter: p.Counter,
		CreatedMs: now().UnixMilli(), CtLen: uint64(ct.Len()),
	}
	fw, err := frame.NewWriter(dst, p.SigningKey, h)
	if err != nil {
		return err
	}
	if _, err := fw.Write(ct.Bytes()); err != nil {
		return err
	}
	return fw.Close()
}

// SealBytes is Seal returning the frame as a byte slice.
func SealBytes(p SealParams, ctype uint8, body []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := Seal(&b, p, ctype, body); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// OpenParams configure Open.
type OpenParams struct {
	// GroupID the item must belong to.
	GroupID [16]byte
	// Lookup resolves sender ids to Ed25519 keys (the roster); unknown senders are rejected.
	Lookup frame.KeyLookup
	// Identity decrypts the item.
	Identity age.Identity
	// LastCounter is the highest counter already accepted from this sender;
	// items with counter <= LastCounter are rejected. The caller persists the
	// new value (Item.Header.Counter) after a successful Open.
	LastCounter func(sender [16]byte) uint64
	// TTL is the relay item lifetime (default 10 min); items older than
	// TTL+ClockSkew are rejected, as are items more than ClockSkew in the future.
	TTL time.Duration
	// Now returns the current time; nil means time.Now.
	Now    func() time.Time
	Limits Limits
}

// Item is a successfully opened clipboard item.
type Item struct {
	Header frame.Header
	CType  uint8
	Body   []byte
}

// Open verifies and decrypts a frame read from src. Order: header checks
// (group, sender known, replay, timestamp, size) -> signature -> decrypt ->
// limit-enforced decompress.
func Open(src io.Reader, p OpenParams) (*Item, error) {
	lim := p.Limits.norm()
	ttl := p.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	v := &frame.Verifier{
		Lookup:        p.Lookup,
		MaxCiphertext: lim.MaxCiphertext,
		CheckHeader: func(h frame.Header) error {
			if h.GroupID != p.GroupID {
				return ErrWrongGroup
			}
			var last uint64
			if p.LastCounter != nil {
				last = p.LastCounter(h.SenderID)
			}
			if h.Counter == 0 || h.Counter <= last {
				return ErrReplay
			}
			n := now()
			created := time.UnixMilli(h.CreatedMs)
			if n.Sub(created) > ttl+ClockSkew {
				return ErrExpired
			}
			if created.Sub(n) > ClockSkew {
				return ErrFuture
			}
			return nil
		},
	}
	var ct bytes.Buffer
	h, err := v.Verify(src, &ct)
	if err != nil {
		return nil, err
	}
	// Signature is valid from here on.
	pr, err := age.Decrypt(&ct, p.Identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	var ih [innerHeaderSize]byte
	if _, err := io.ReadFull(pr, ih[:]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadInner, err)
	}
	ctype, comp, rawLen := ih[0], ih[1], getU64(ih[2:])
	max, err := lim.forType(ctype)
	if err != nil {
		return nil, err
	}
	if rawLen > max {
		return nil, fmt.Errorf("%w: raw_len %d > %d", ErrTooBig, rawLen, max)
	}
	var body []byte
	switch comp {
	case compNone:
		body, err = readExactly(pr, rawLen)
	case compZstd:
		if ctype != CTypeText {
			return nil, fmt.Errorf("%w: compressed non-text", ErrBadInner)
		}
		body, err = decodeZstd(pr, rawLen)
	default:
		return nil, fmt.Errorf("%w: comp %d", ErrBadInner, comp)
	}
	if err != nil {
		return nil, err
	}
	// Drain to EOF so age authenticates the final chunk and no trailing
	// plaintext is silently ignored.
	var extra [1]byte
	if n, err := io.ReadFull(pr, extra[:]); n > 0 {
		return nil, fmt.Errorf("%w: trailing plaintext", ErrBadInner)
	} else if err != io.EOF {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if ctype == CTypeText && !utf8.Valid(body) {
		return nil, ErrBadText
	}
	if ctype == CTypeImagePNG && !hasPNGSig(body) {
		return nil, fmt.Errorf("%w: missing PNG signature", ErrBadInner)
	}
	return &Item{Header: h, CType: ctype, Body: body}, nil
}

var pngSig = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

func hasPNGSig(b []byte) bool { return bytes.HasPrefix(b, pngSig) }

// OpenBytes is Open on a byte slice.
func OpenBytes(frameBytes []byte, p OpenParams) (*Item, error) {
	return Open(bytes.NewReader(frameBytes), p)
}

// readExactly reads exactly n bytes and requires EOF afterwards.
func readExactly(r io.Reader, n uint64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(n)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	if uint64(len(b)) != n {
		return nil, fmt.Errorf("%w: body length %d != raw_len %d", ErrBadInner, len(b), n)
	}
	return b, nil
}

var (
	encOnce sync.Once
	enc     *zstd.Encoder
)

func encodeZstd(b []byte) []byte {
	encOnce.Do(func() {
		var err error
		enc, err = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if err != nil {
			panic(err) // static options; cannot fail
		}
	})
	return enc.EncodeAll(b, nil)
}

// decodeZstd decompresses r, never producing more than want+1 bytes, and
// requires the result to be exactly want bytes (zstd bomb / lying raw_len guard).
func decodeZstd(r io.Reader, want uint64) ([]byte, error) {
	dec, err := zstd.NewReader(r,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(want+(1<<20)),
		zstd.WithDecoderMaxWindow(64<<20),
	)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	b, err := io.ReadAll(io.LimitReader(dec, int64(want)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: zstd: %v", ErrBadInner, err)
	}
	if uint64(len(b)) != want {
		return nil, fmt.Errorf("%w: decoded %d bytes, raw_len %d", ErrBadInner, len(b), want)
	}
	return b, nil
}

func putU64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

func getU64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}
