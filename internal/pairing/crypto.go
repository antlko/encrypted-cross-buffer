package pairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/schollz/pake/v3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

const (
	curve     = "p256"
	roleA     = 0
	roleB     = 1
	maxMsg    = 16 << 10
	labelConf = "ecb-confirm-"
)

var (
	// ErrConfirmation means key confirmation failed: wrong code or a relay
	// that tampered with the exchange.
	ErrConfirmation = errors.New("pairing: key confirmation failed (wrong code, or the relay tampered with the exchange)")
	// ErrTimeout means the peer did not answer in time.
	ErrTimeout = errors.New("pairing: timed out waiting for the other device")
	// ErrBadMessage means a message was malformed or failed authentication.
	ErrBadMessage = errors.New("pairing: malformed or unauthenticated message")
	// ErrRejected means the descriptor or roster was not acceptable.
	ErrRejected = errors.New("pairing: rejected")
)

// pakeSession wraps a pake.Pake, allowing exactly one Update (the library
// silently overwrites K on a second call) and turning panics on hostile input
// into errors.
type pakeSession struct {
	p       *pake.Pake
	updated bool
}

func newPake(c Code, role int) (*pakeSession, error) {
	id := []byte("ecb-pair-v1|" + strconv.Itoa(c.Mailbox))
	p, err := pake.InitCurveWithIdentities([]byte(c.String()), role, curve, id, id)
	if err != nil {
		return nil, fmt.Errorf("pairing: pake init: %w", err)
	}
	return &pakeSession{p: p}, nil
}

func (s *pakeSession) bytes() []byte { return s.p.Bytes() }

func (s *pakeSession) update(peer []byte) (err error) {
	if s.updated {
		return errors.New("pairing: pake update called twice")
	}
	s.updated = true
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: invalid pake message", ErrBadMessage)
		}
	}()
	if len(peer) == 0 || len(peer) > maxMsg {
		return ErrBadMessage
	}
	if err := s.p.Update(peer); err != nil {
		return fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	return nil
}

func (s *pakeSession) key() ([]byte, error) {
	if !s.updated || !s.p.HaveSessionKey() {
		return nil, errors.New("pairing: no session key")
	}
	return s.p.SessionKey()
}

type keys struct{ confirm, enc []byte }

func deriveKeys(k []byte) (keys, error) {
	r := hkdf.New(sha256.New, k, nil, []byte("ecb-pair-keys-v1"))
	buf := make([]byte, 64)
	if _, err := io.ReadFull(r, buf); err != nil {
		return keys{}, err
	}
	return keys{confirm: buf[:32], enc: buf[32:]}, nil
}

// transcript is the length-prefixed concatenation of both PAKE messages.
func transcript(msg1, msg2 []byte) []byte {
	var b bytes.Buffer
	for _, m := range [][]byte{msg1, msg2} {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(m)))
		b.Write(m)
	}
	return b.Bytes()
}

func confirmMAC(k keys, who string, tr []byte) []byte {
	h := hmac.New(sha256.New, k.confirm)
	h.Write([]byte(labelConf + who))
	h.Write(tr)
	return h.Sum(nil)
}

func checkMAC(k keys, who string, tr, got []byte) error {
	if !hmac.Equal(confirmMAC(k, who, tr), got) {
		return ErrConfirmation
	}
	return nil
}

func seal(k keys, label string, mailbox int, pt []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.enc)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, []byte(label+strconv.Itoa(mailbox))), nil
}

func open(k keys, label string, mailbox int, msg []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(k.enc)
	if err != nil {
		return nil, err
	}
	if len(msg) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrBadMessage
	}
	pt, err := aead.Open(nil, msg[:aead.NonceSize()], msg[aead.NonceSize():], []byte(label+strconv.Itoa(mailbox)))
	if err != nil {
		return nil, ErrBadMessage
	}
	return pt, nil
}

// verifyBootstrapRoster checks a roster that arrived over the authenticated
// pairing channel (PAKE + mutual key confirmation + AEAD). roster.Verify(nil)
// only accepts a version-1, single-member genesis, but the roster a joiner
// receives is always version >= 2 (the inviter has just added the joiner), so
// there is no held roster to verify against. Trust-on-first-use is acceptable
// here ONLY because the bytes come through the authenticated channel, never
// from the relay: we require a structurally valid roster whose signer is one
// of its own members and whose signature verifies under that member's key.
// Subsequent rosters are verified normally against this one with Verify.
func verifyBootstrapRoster(r *roster.Roster) error {
	if r.Version < 2 {
		return fmt.Errorf("%w: roster version %d", ErrRejected, r.Version)
	}
	signer, ok := r.Lookup(r.Signer)
	if !ok {
		return fmt.Errorf("%w: signer is not a member", ErrRejected)
	}
	raw, err := r.Marshal()
	if err != nil || len(raw) <= ed25519.SignatureSize {
		return fmt.Errorf("%w: cannot marshal roster", ErrRejected)
	}
	// Mirrors roster's signed message: "ecb-roster-v1" || body.
	body := raw[:len(raw)-ed25519.SignatureSize]
	msg := append([]byte("ecb-roster-v1"), body...)
	if len(signer.Ed25519) != ed25519.PublicKeySize || !ed25519.Verify(signer.Ed25519, msg, r.Sig) {
		return roster.ErrBadSignature
	}
	// Re-parse to apply the strict structural validation.
	if _, err := roster.Unmarshal(raw); err != nil {
		return err
	}
	return nil
}
