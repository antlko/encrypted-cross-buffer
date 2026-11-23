// Package pairing implements device pairing: a PAKE (schollz/pake, P-256)
// run through the relay's pairing mailbox, followed by mandatory mutual key
// confirmation and an authenticated exchange of the device descriptor and the
// signed roster. The relay only ever sees opaque messages; a wrong code or a
// tampering relay makes the key confirmation fail, and nothing is published.
package pairing

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

//go:embed wordlist.txt
var wordlistRaw string

var words = func() []string {
	w := strings.Fields(wordlistRaw)
	if len(w) != 2048 {
		panic("pairing: embedded wordlist must have 2048 words")
	}
	return w
}()

// MinSecretLen is the minimum length of a user-chosen secret.
const MinSecretLen = 8

// MaxMailbox is the highest mailbox number the relay hands out.
const MaxMailbox = 99

// Code is a pairing code: "<mailbox>-<secret>", e.g. "7-orbit-velvet-candle".
type Code struct {
	Mailbox int
	Secret  string
}

// String returns the normalised code, which is also the PAKE password.
func (c Code) String() string { return strconv.Itoa(c.Mailbox) + "-" + c.Secret }

// RandomSecret returns three random words from the embedded list (~33 bits).
func RandomSecret() (string, error) {
	var parts [3]string
	for i := range parts {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		parts[i] = words[(int(b[0])<<8|int(b[1]))&0x7ff] // 2048 = 2^11: uniform
	}
	return strings.Join(parts[:], "-"), nil
}

// NewCode builds a code for mailbox. An empty secret selects a random one.
func NewCode(mailbox int, secret string) (Code, error) {
	if mailbox < 1 || mailbox > MaxMailbox {
		return Code{}, fmt.Errorf("pairing: mailbox %d out of range", mailbox)
	}
	if secret == "" {
		s, err := RandomSecret()
		if err != nil {
			return Code{}, err
		}
		return Code{mailbox, s}, nil
	}
	secret = normalise(secret)
	if len(secret) < MinSecretLen {
		return Code{}, fmt.Errorf("pairing: secret must be at least %d characters", MinSecretLen)
	}
	return Code{mailbox, secret}, nil
}

// SecretWarning returns a non-empty warning when a user-chosen secret is weak.
// PAKE prevents offline guessing, but one online guess per pairing remains.
func SecretWarning(secret string) string {
	s := normalise(secret)
	if len(s) < 12 {
		return "this secret is short; anyone who guesses it during the 5 minute window can join your group. Prefer the generated words or 12+ random characters"
	}
	return ""
}

// ParseCode parses a code typed by the user.
func ParseCode(s string) (Code, error) {
	s = normalise(s)
	num, rest, ok := strings.Cut(s, "-")
	n, err := strconv.Atoi(num)
	if !ok || err != nil || n < 1 || n > MaxMailbox || rest == "" {
		return Code{}, errors.New("pairing: invalid code (expected like 7-orbit-velvet-candle)")
	}
	return Code{n, rest}, nil
}

func normalise(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
