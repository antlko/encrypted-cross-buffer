package frame

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func testKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pk, sk
}

func sample(ct []byte) Header {
	h := Header{Flags: 0, Counter: 7, CreatedMs: 1700000000000, CtLen: uint64(len(ct))}
	for i := range h.GroupID {
		h.GroupID[i] = byte(i + 1)
		h.SenderID[i] = byte(100 + i)
	}
	return h
}

func build(t testing.TB, sk ed25519.PrivateKey, h Header, ct []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, sk, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(ct); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func verifier(pk ed25519.PublicKey, h Header) *Verifier {
	return &Verifier{Lookup: func(id [16]byte) (ed25519.PublicKey, bool) {
		if id == h.SenderID {
			return pk, true
		}
		return nil, false
	}}
}

func TestHeaderRoundTrip(t *testing.T) {
	h := sample(make([]byte, 5))
	b := h.Marshal()
	if len(b) != 62 || string(b[:4]) != "ECB1" || b[4] != 1 {
		t.Fatalf("bad layout % x", b[:8])
	}
	got, err := ParseHeader(b[:], 0)
	if err != nil || got != h {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestHeaderStrict(t *testing.T) {
	h := sample(nil)
	good := h.Marshal()
	cases := map[string]func([]byte) ([]byte, error){
		"magic":   func(b []byte) ([]byte, error) { b[0] = 'X'; return b, ErrBadMagic },
		"version": func(b []byte) ([]byte, error) { b[4] = 2; return b, ErrBadVersion },
		"short":   func(b []byte) ([]byte, error) { return b[:61], ErrShortHeader },
		"long":    func(b []byte) ([]byte, error) { return append(b, 0), ErrShortHeader },
		"oversize": func(b []byte) ([]byte, error) {
			for i := 54; i < 62; i++ {
				b[i] = 0xff
			}
			return b, ErrTooLarge
		},
	}
	for name, mut := range cases {
		b := append([]byte(nil), good[:]...)
		b, want := mut(b)
		if _, err := ParseHeader(b, 0); !errors.Is(err, want) {
			t.Errorf("%s: got %v want %v", name, err, want)
		}
	}
	h.CtLen = 101
	b := h.Marshal()
	if _, err := ParseHeader(b[:], 100); !errors.Is(err, ErrTooLarge) {
		t.Errorf("custom max: %v", err)
	}
	h.CtLen = 100
	b = h.Marshal()
	if _, err := ParseHeader(b[:], 100); err != nil {
		t.Errorf("at limit: %v", err)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	ct := make([]byte, 300000)
	rand.Read(ct)
	pk, sk := testKey(t)
	h := sample(ct)
	wire := build(t, sk, h, ct)
	if len(wire) != HeaderSize+len(ct)+SigSize {
		t.Fatalf("size %d", len(wire))
	}
	var dst bytes.Buffer
	got, err := verifier(pk, h).Verify(iotest.OneByteReader(bytes.NewReader(wire)), &dst)
	if err != nil || got != h || !bytes.Equal(dst.Bytes(), ct) {
		t.Fatalf("err=%v", err)
	}
}

func TestEmptyCiphertext(t *testing.T) {
	pk, sk := testKey(t)
	h := sample(nil)
	var dst bytes.Buffer
	if _, err := verifier(pk, h).Verify(bytes.NewReader(build(t, sk, h, nil)), &dst); err != nil {
		t.Fatal(err)
	}
}

func TestRejects(t *testing.T) {
	ct := bytes.Repeat([]byte("abc"), 100)
	pk, sk := testKey(t)
	h := sample(ct)
	wire := build(t, sk, h, ct)
	v := verifier(pk, h)

	flip := func(i int) []byte {
		b := append([]byte(nil), wire...)
		b[i] ^= 1
		return b
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"tampered header counter", flip(40), ErrBadSignature},
		{"reserved flag bit set", flip(5), ErrBadFlags},
		{"tampered ct", flip(HeaderSize + 10), ErrBadSignature},
		{"tampered sig", flip(len(wire) - 1), ErrBadSignature},
		{"truncated in ct", wire[:HeaderSize+10], ErrTruncated},
		{"truncated sig", wire[:len(wire)-1], ErrTruncated},
		{"truncated header", wire[:30], ErrShortHeader},
		{"empty", nil, ErrShortHeader},
		{"trailing", append(append([]byte(nil), wire...), 0), ErrTrailingData},
		{"bad magic", flip(0), ErrBadMagic},
		{"sender changed", flip(22), ErrUnknownSender},
	}
	for _, c := range cases {
		var dst bytes.Buffer
		if _, err := v.Verify(bytes.NewReader(c.in), &dst); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestWrongKey(t *testing.T) {
	ct := []byte("hello")
	_, sk := testKey(t)
	other, _ := testKey(t)
	h := sample(ct)
	_, err := verifier(other, h).Verify(bytes.NewReader(build(t, sk, h, ct)), io.Discard)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestOversizeRejectedBeforeCopy(t *testing.T) {
	pk, sk := testKey(t)
	ct := make([]byte, 1000)
	h := sample(ct)
	v := verifier(pk, h)
	v.MaxCiphertext = 999
	var dst bytes.Buffer
	if _, err := v.Verify(bytes.NewReader(build(t, sk, h, ct)), &dst); !errors.Is(err, ErrTooLarge) || dst.Len() != 0 {
		t.Fatalf("err=%v written=%d", err, dst.Len())
	}
}

func TestCheckHeaderRunsBeforeCopy(t *testing.T) {
	pk, sk := testKey(t)
	ct := make([]byte, 1000)
	h := sample(ct)
	v := verifier(pk, h)
	sentinel := errors.New("nope")
	v.CheckHeader = func(Header) error { return sentinel }
	var dst bytes.Buffer
	if _, err := v.Verify(bytes.NewReader(build(t, sk, h, ct)), &dst); !errors.Is(err, sentinel) || dst.Len() != 0 {
		t.Fatalf("err=%v written=%d", err, dst.Len())
	}
}

func TestWriterLengthEnforced(t *testing.T) {
	_, sk := testKey(t)
	h := sample(make([]byte, 10))
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, sk, h)
	w.Write(make([]byte, 5))
	if err := w.Close(); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("short: %v", err)
	}
	buf.Reset()
	w, _ = NewWriter(&buf, sk, h)
	if _, err := w.Write(make([]byte, 11)); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("long: %v", err)
	}
}

func FuzzParseHeader(f *testing.F) {
	h := sample(make([]byte, 3))
	b := h.Marshal()
	f.Add(b[:])
	f.Add([]byte("ECB1"))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseHeader(in, 0)
		if err != nil {
			return
		}
		m := got.Marshal()
		if !bytes.Equal(m[:], in) {
			t.Fatalf("not canonical: % x vs % x", m, in)
		}
	})
}

func FuzzVerify(f *testing.F) {
	pk, sk := testKey(f)
	ct := []byte("data")
	h := sample(ct)
	f.Add(build(f, sk, h, ct))
	f.Fuzz(func(t *testing.T, in []byte) {
		v := verifier(pk, h)
		v.MaxCiphertext = 1 << 16
		// Must not panic; random input is overwhelmingly rejected.
		v.Verify(bytes.NewReader(in), io.Discard)
	})
}

func TestReservedFlagsRejected(t *testing.T) {
	h := sample(nil)
	h.Flags = 0x80
	if _, err := ParseHeader(append([]byte(nil), func() []byte { b := h.Marshal(); return b[:] }()...), 0); !errors.Is(err, ErrBadFlags) {
		t.Fatalf("parse: %v", err)
	}
	_, sk := testKey(t)
	if _, err := NewWriter(io.Discard, sk, h); !errors.Is(err, ErrBadFlags) {
		t.Fatalf("writer: %v", err)
	}
}

func TestSignatureDomainSeparation(t *testing.T) {
	pk, sk := testKey(t)
	h := sample([]byte("ct"))
	hdr := h.Marshal()
	hash := sha256.Sum256([]byte("ct"))
	if !VerifySig(pk, hdr, hash, Sign(sk, hdr, hash)) {
		t.Fatal("control failed")
	}
	// Signature over header||SHA256(ct) without the "ecb-item-v1" prefix.
	bare := ed25519.Sign(sk, append(append([]byte(nil), hdr[:]...), hash[:]...))
	if VerifySig(pk, hdr, hash, bare) {
		t.Fatal("signature without domain prefix verified")
	}
	// A different context prefix must not verify either.
	other := ed25519.Sign(sk, append(append([]byte("ecb-roster-v1"), hdr[:]...), hash[:]...))
	if VerifySig(pk, hdr, hash, other) {
		t.Fatal("signature with foreign context verified")
	}
}

// TestSignatureKnownAnswer pins the signed byte layout; any change to it
// (prefix, field order, hash) changes the signature and fails this test.
func TestSignatureKnownAnswer(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	ct := []byte("ecb known answer ciphertext")
	h := sample(ct)
	hdr := h.Marshal()
	hash := sha256.Sum256(ct)
	sig := Sign(sk, hdr, hash)
	got := hex.EncodeToString(sig)
	const want = "4754fb5efc6f76f383625e3803693f0bd933ce861a7987628a4318aa0f9e185ef71f39e047d5e2604b7e2a63cec190fc0a4d42c9965557fb4839698e0f4b4d0a"
	if got != want {
		t.Fatalf("signature layout changed:\n got %s\nwant %s", got, want)
	}
	if !VerifySig(sk.Public().(ed25519.PublicKey), hdr, hash, sig) {
		t.Fatal("verify failed")
	}
}
