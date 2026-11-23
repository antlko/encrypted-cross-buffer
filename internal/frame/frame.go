// Package frame implements the outer binary frame v1 of an ecb item.
//
// Wire layout (all integers big-endian):
//
//	magic "ECB1"(4) | ver u8=1 | flags u8 | group_id[16] | sender_id[16] |
//	counter u64 | created_ms i64 | ct_len u64 | ct[ct_len] | sig[64]
//
// The header is the first HeaderSize (62) bytes. The signature is
//
//	sig = Ed25519(sk, "ecb-item-v1" || header_bytes || SHA-256(ct))
//
// The package is streaming: neither the Writer nor the Verifier buffers the
// ciphertext, so a relay can check an item while spooling it to disk.
package frame

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

const (
	// Version is the only supported frame version.
	Version = 1
	// HeaderSize is the size in bytes of the marshalled header.
	HeaderSize = 62
	// SigSize is the size of the trailing Ed25519 signature.
	SigSize = ed25519.SignatureSize
	// DefaultMaxCiphertext is the default ct_len limit (32 MiB).
	DefaultMaxCiphertext = 32 << 20

	sigContext = "ecb-item-v1"
)

var magic = [4]byte{'E', 'C', 'B', '1'}

// Errors returned by the package. Use errors.Is.
var (
	ErrShortHeader    = errors.New("frame: short header")
	ErrBadMagic       = errors.New("frame: bad magic")
	ErrBadVersion     = errors.New("frame: unsupported version")
	ErrTooLarge       = errors.New("frame: ciphertext length exceeds limit")
	ErrTruncated      = errors.New("frame: truncated frame")
	ErrTrailingData   = errors.New("frame: trailing data after signature")
	ErrUnknownSender  = errors.New("frame: unknown sender")
	ErrBadSignature   = errors.New("frame: signature verification failed")
	ErrLengthMismatch = errors.New("frame: written length differs from ct_len")
)

// Header is the parsed outer frame header.
type Header struct {
	Flags     uint8
	GroupID   [16]byte
	SenderID  [16]byte
	Counter   uint64
	CreatedMs int64
	CtLen     uint64
}

// Marshal returns the 62-byte wire form of the header.
func (h Header) Marshal() [HeaderSize]byte {
	var b [HeaderSize]byte
	copy(b[0:4], magic[:])
	b[4] = Version
	b[5] = h.Flags
	copy(b[6:22], h.GroupID[:])
	copy(b[22:38], h.SenderID[:])
	binary.BigEndian.PutUint64(b[38:46], h.Counter)
	binary.BigEndian.PutUint64(b[46:54], uint64(h.CreatedMs))
	binary.BigEndian.PutUint64(b[54:62], h.CtLen)
	return b
}

// ParseHeader strictly parses exactly HeaderSize bytes. maxCt is the largest
// accepted ct_len; 0 means DefaultMaxCiphertext.
func ParseHeader(b []byte, maxCt uint64) (Header, error) {
	var h Header
	if len(b) != HeaderSize {
		return h, ErrShortHeader
	}
	if !bytes.Equal(b[0:4], magic[:]) {
		return h, ErrBadMagic
	}
	if b[4] != Version {
		return h, fmt.Errorf("%w: %d", ErrBadVersion, b[4])
	}
	if maxCt == 0 {
		maxCt = DefaultMaxCiphertext
	}
	if maxCt > math.MaxInt64 {
		maxCt = math.MaxInt64
	}
	h.Flags = b[5]
	copy(h.GroupID[:], b[6:22])
	copy(h.SenderID[:], b[22:38])
	h.Counter = binary.BigEndian.Uint64(b[38:46])
	h.CreatedMs = int64(binary.BigEndian.Uint64(b[46:54]))
	h.CtLen = binary.BigEndian.Uint64(b[54:62])
	if h.CtLen > maxCt {
		return Header{}, fmt.Errorf("%w: %d > %d", ErrTooLarge, h.CtLen, maxCt)
	}
	return h, nil
}

// ReadHeader reads and parses a header from r.
func ReadHeader(r io.Reader, maxCt uint64) (Header, error) {
	var b [HeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Header{}, fmt.Errorf("%w: %v", ErrShortHeader, err)
	}
	return ParseHeader(b[:], maxCt)
}

// signedMessage builds the byte string covered by the signature.
func signedMessage(header []byte, ctHash []byte) []byte {
	m := make([]byte, 0, len(sigContext)+len(header)+len(ctHash))
	m = append(m, sigContext...)
	m = append(m, header...)
	return append(m, ctHash...)
}

// Sign computes the frame signature for a marshalled header and ct hash.
func Sign(sk ed25519.PrivateKey, header [HeaderSize]byte, ctHash [sha256.Size]byte) []byte {
	return ed25519.Sign(sk, signedMessage(header[:], ctHash[:]))
}

// VerifySig checks a frame signature.
func VerifySig(pk ed25519.PublicKey, header [HeaderSize]byte, ctHash [sha256.Size]byte, sig []byte) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != SigSize {
		return false
	}
	return ed25519.Verify(pk, signedMessage(header[:], ctHash[:]), sig)
}

// Writer streams one frame to an underlying writer. Create it with NewWriter
// (which writes the header), Write exactly Header.CtLen ciphertext bytes, then
// Close to append the signature. Close does not close the underlying writer.
type Writer struct {
	w      io.Writer
	sk     ed25519.PrivateKey
	hdr    [HeaderSize]byte
	remain uint64
	hash   hash.Hash
	err    error
	closed bool
}

// NewWriter writes h to w and returns a Writer for the ciphertext.
func NewWriter(w io.Writer, sk ed25519.PrivateKey, h Header) (*Writer, error) {
	if len(sk) != ed25519.PrivateKeySize {
		return nil, errors.New("frame: invalid signing key")
	}
	fw := &Writer{w: w, sk: sk, hdr: h.Marshal(), remain: h.CtLen, hash: sha256.New()}
	if _, err := w.Write(fw.hdr[:]); err != nil {
		return nil, err
	}
	return fw, nil
}

// Write writes ciphertext bytes; it fails if more than CtLen bytes are written.
func (fw *Writer) Write(p []byte) (int, error) {
	if fw.err != nil {
		return 0, fw.err
	}
	if fw.closed {
		return 0, errors.New("frame: write after close")
	}
	if uint64(len(p)) > fw.remain {
		fw.err = ErrLengthMismatch
		return 0, fw.err
	}
	n, err := fw.w.Write(p)
	fw.hash.Write(p[:n])
	fw.remain -= uint64(n)
	if err != nil {
		fw.err = err
	}
	return n, err
}

// Close verifies that exactly CtLen bytes were written and appends the signature.
func (fw *Writer) Close() error {
	if fw.closed {
		return fw.err
	}
	fw.closed = true
	if fw.err != nil {
		return fw.err
	}
	if fw.remain != 0 {
		fw.err = ErrLengthMismatch
		return fw.err
	}
	var sum [sha256.Size]byte
	fw.hash.Sum(sum[:0])
	_, fw.err = fw.w.Write(Sign(fw.sk, fw.hdr, sum))
	return fw.err
}

// KeyLookup resolves a sender id to its Ed25519 public key.
type KeyLookup func(senderID [16]byte) (ed25519.PublicKey, bool)

// Verifier reads one frame from a stream, copying the ciphertext to a
// destination writer while hashing it, and checks the signature.
//
// The ciphertext reaches dst BEFORE the signature is known to be valid, so on
// any error the caller MUST discard whatever was written to dst (e.g. delete
// the temp file). Memory use is constant regardless of ct_len.
type Verifier struct {
	// Lookup resolves sender keys; required.
	Lookup KeyLookup
	// MaxCiphertext limits ct_len; 0 means DefaultMaxCiphertext.
	MaxCiphertext uint64
	// CheckHeader, if set, runs after the header is parsed and the sender is
	// known but before any ciphertext is copied (e.g. group, replay, age checks).
	CheckHeader func(Header) error
}

// Verify consumes exactly one frame from src. After the signature, src must be
// at EOF, otherwise ErrTrailingData is returned. On success the parsed header
// is returned.
func (v *Verifier) Verify(src io.Reader, dst io.Writer) (Header, error) {
	var hb [HeaderSize]byte
	if _, err := io.ReadFull(src, hb[:]); err != nil {
		return Header{}, fmt.Errorf("%w: %v", ErrShortHeader, err)
	}
	h, err := ParseHeader(hb[:], v.MaxCiphertext)
	if err != nil {
		return Header{}, err
	}
	pk, ok := v.Lookup(h.SenderID)
	if !ok {
		return Header{}, ErrUnknownSender
	}
	if v.CheckHeader != nil {
		if err := v.CheckHeader(h); err != nil {
			return Header{}, err
		}
	}
	hs := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, hs), io.LimitReader(src, int64(h.CtLen)))
	if err != nil {
		return Header{}, err
	}
	if uint64(n) != h.CtLen {
		return Header{}, ErrTruncated
	}
	var sig [SigSize]byte
	if _, err := io.ReadFull(src, sig[:]); err != nil {
		return Header{}, ErrTruncated
	}
	var one [1]byte
	if _, err := io.ReadFull(src, one[:]); err == nil {
		return Header{}, ErrTrailingData
	}
	var sum [sha256.Size]byte
	hs.Sum(sum[:0])
	if !VerifySig(pk, hb, sum, sig[:]) {
		return Header{}, ErrBadSignature
	}
	return h, nil
}
