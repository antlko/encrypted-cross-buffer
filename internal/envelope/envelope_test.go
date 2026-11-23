package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/frame"
)

var t0 = time.Unix(1_800_000_000, 0)

type dev struct {
	id    [16]byte
	pk    ed25519.PublicKey
	sk    ed25519.PrivateKey
	ident *age.X25519Identity
}

func newDev(t testing.TB, n byte) *dev {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	d := &dev{pk: pk, sk: sk, ident: id}
	d.id[0] = n
	return d
}

type env struct {
	group  [16]byte
	sender *dev
	rcpts  []*dev
	now    time.Time
}

func newEnv(t testing.TB, nr int) *env {
	e := &env{sender: newDev(t, 1), now: t0}
	e.group[0] = 9
	for i := 0; i < nr; i++ {
		e.rcpts = append(e.rcpts, newDev(t, byte(10+i)))
	}
	return e
}

func (e *env) seal(t testing.TB, counter uint64, ctype uint8, body []byte) []byte {
	t.Helper()
	var rs []age.Recipient
	for _, r := range e.rcpts {
		rs = append(rs, r.ident.Recipient())
	}
	b, err := SealBytes(SealParams{GroupID: e.group, SenderID: e.sender.id, SigningKey: e.sender.sk,
		Recipients: rs, Counter: counter, Now: func() time.Time { return e.now }}, ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *env) open(r *dev, last uint64, in []byte) (*Item, error) {
	return OpenBytes(in, e.openParams(r, last))
}

func (e *env) openParams(r *dev, last uint64) OpenParams {
	return OpenParams{
		GroupID: e.group, Identity: r.ident, Now: func() time.Time { return e.now },
		Lookup: func(id [16]byte) (ed25519.PublicKey, bool) {
			if id == e.sender.id {
				return e.sender.pk, true
			}
			return nil, false
		},
		LastCounter: func([16]byte) uint64 { return last },
	}
}

func TestRoundTripText(t *testing.T) {
	e := newEnv(t, 1)
	var lines strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&lines, "line %d: the quick brown fox jumps over the lazy dog\n", i)
	}
	big := make([]byte, 1<<20)
	for i := range big {
		big[i] = 'a' + byte(i*7%23)
	}
	for name, body := range map[string][]byte{
		"small": []byte("hello, мир"), "empty": {}, "10k lines": []byte(lines.String()), "1MiB": big,
	} {
		w := e.seal(t, 5, CTypeText, body)
		it, err := e.open(e.rcpts[0], 4, w)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if it.CType != CTypeText || !bytes.Equal(it.Body, body) || it.Header.Counter != 5 {
			t.Fatalf("%s: mismatch", name)
		}
	}
	// Compression actually happens on compressible text.
	if w := e.seal(t, 1, CTypeText, []byte(lines.String())); len(w) > len(lines.String())/4 {
		t.Fatalf("not compressed: %d of %d", len(w), lines.Len())
	}
}

func TestIncompressibleStoredRaw(t *testing.T) {
	e := newEnv(t, 1)
	s := []byte("x") // 1 byte: zstd cannot shrink it
	if _, err := e.open(e.rcpts[0], 0, e.seal(t, 1, CTypeText, s)); err != nil {
		t.Fatal(err)
	}
	if c := encodeZstd(s); len(c) < len(s) {
		t.Fatal("expected zstd not to shrink 1 byte")
	}
}

func TestRoundTripPNG(t *testing.T) {
	e := newEnv(t, 1)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8}, 5000)...)
	it, err := e.open(e.rcpts[0], 0, e.seal(t, 1, CTypeImagePNG, png))
	if err != nil || it.CType != CTypeImagePNG || !bytes.Equal(it.Body, png) {
		t.Fatalf("err=%v", err)
	}
}

func TestMultiRecipient(t *testing.T) {
	e := newEnv(t, 3)
	w := e.seal(t, 1, CTypeText, []byte("secret"))
	for i, r := range e.rcpts {
		it, err := e.open(r, 0, w)
		if err != nil || string(it.Body) != "secret" {
			t.Fatalf("recipient %d: %v", i, err)
		}
	}
	out := newDev(t, 99)
	if _, err := e.open(out, 0, w); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("outsider: %v", err)
	}
}

func TestTamperedRejected(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte(strings.Repeat("hello ", 100)))
	for _, off := range []int{6, 22, 40, 50, frame.HeaderSize + 20, len(w) - 70, len(w) - 1} {
		c := append([]byte(nil), w...)
		c[off] ^= 0x80
		if _, err := e.open(e.rcpts[0], 0, c); err == nil {
			t.Errorf("tamper at %d accepted", off)
		}
	}
}

func TestSignatureCheckedBeforeDecrypt(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte("hello hello hello hello"))
	w[frame.HeaderSize+5] ^= 1
	if _, err := e.open(e.rcpts[0], 0, w); !errors.Is(err, frame.ErrBadSignature) {
		t.Fatalf("got %v, want signature error (not a decrypt error)", err)
	}
}

func TestWrongSender(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte("hi"))
	// Receiver trusts a different key for that sender id.
	p := e.openParams(e.rcpts[0], 0)
	other := newDev(t, 1)
	p.Lookup = func([16]byte) (ed25519.PublicKey, bool) { return other.pk, true }
	if _, err := OpenBytes(w, p); !errors.Is(err, frame.ErrBadSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	p.Lookup = func([16]byte) (ed25519.PublicKey, bool) { return nil, false }
	if _, err := OpenBytes(w, p); !errors.Is(err, frame.ErrUnknownSender) {
		t.Fatalf("unknown: %v", err)
	}
	// An attacker signing with own key but claiming the sender id.
	atk := newDev(t, 1)
	e2 := &env{group: e.group, sender: atk, rcpts: e.rcpts, now: e.now}
	if _, err := e.open(e.rcpts[0], 0, e2.seal(t, 1, CTypeText, []byte("hi"))); !errors.Is(err, frame.ErrBadSignature) {
		t.Fatalf("forged: %v", err)
	}
}

func TestWrongGroup(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte("hi"))
	p := e.openParams(e.rcpts[0], 0)
	p.GroupID[0] = 1
	if _, err := OpenBytes(w, p); !errors.Is(err, ErrWrongGroup) {
		t.Fatal(err)
	}
}

func TestReplay(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 5, CTypeText, []byte("hi"))
	for _, last := range []uint64{5, 6, 100} {
		if _, err := e.open(e.rcpts[0], last, w); !errors.Is(err, ErrReplay) {
			t.Errorf("last=%d: %v", last, err)
		}
	}
	if _, err := e.open(e.rcpts[0], 4, w); err != nil {
		t.Fatal(err)
	}
}

func TestTimestamps(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte("hi"))
	cases := []struct {
		shift time.Duration
		want  error
	}{
		{0, nil},
		{DefaultTTL + ClockSkew - time.Second, nil},
		{DefaultTTL + ClockSkew + time.Second, ErrExpired},
		{-ClockSkew + time.Second, nil},
		{-ClockSkew - time.Second, ErrFuture},
	}
	for _, c := range cases {
		p := e.openParams(e.rcpts[0], 0)
		p.Now = func() time.Time { return t0.Add(c.shift) }
		if _, err := OpenBytes(w, p); !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
			t.Errorf("shift %v: got %v want %v", c.shift, err, c.want)
		}
	}
}

func TestTruncationAndTrailing(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte(strings.Repeat("abc ", 50)))
	for _, n := range []int{0, 10, frame.HeaderSize, len(w) - 65, len(w) - 1} {
		if _, err := e.open(e.rcpts[0], 0, w[:n]); err == nil {
			t.Errorf("truncated to %d accepted", n)
		}
	}
	if _, err := e.open(e.rcpts[0], 0, append(append([]byte(nil), w...), 'x')); !errors.Is(err, frame.ErrTrailingData) {
		t.Fatalf("trailing: %v", err)
	}
}

func TestOversizeCiphertext(t *testing.T) {
	e := newEnv(t, 1)
	w := e.seal(t, 1, CTypeText, []byte(strings.Repeat("abc ", 50)))
	p := e.openParams(e.rcpts[0], 0)
	p.Limits.MaxCiphertext = 50
	if _, err := OpenBytes(w, p); !errors.Is(err, frame.ErrTooLarge) {
		t.Fatal(err)
	}
}

// sealInner frames an arbitrary inner plaintext, bypassing Seal's checks.
func (e *env) sealInner(t testing.TB, inner []byte) []byte {
	t.Helper()
	var ct bytes.Buffer
	aw, err := age.Encrypt(&ct, e.rcpts[0].ident.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	aw.Write(inner)
	aw.Close()
	var out bytes.Buffer
	fw, err := frame.NewWriter(&out, e.sender.sk, frame.Header{GroupID: e.group, SenderID: e.sender.id,
		Counter: 1, CreatedMs: e.now.UnixMilli(), CtLen: uint64(ct.Len())})
	if err != nil {
		t.Fatal(err)
	}
	fw.Write(ct.Bytes())
	fw.Close()
	return out.Bytes()
}

func inner(ctype, comp uint8, rawLen uint64, body []byte) []byte {
	b := make([]byte, innerHeaderSize, innerHeaderSize+len(body))
	b[0], b[1] = ctype, comp
	putU64(b[2:], rawLen)
	return append(b, body...)
}

func zst(b []byte) []byte {
	enc, _ := zstd.NewWriter(nil)
	return enc.EncodeAll(b, nil)
}

func TestInnerRejections(t *testing.T) {
	e := newEnv(t, 1)
	bomb := zst(make([]byte, 64<<20)) // tiny compressed, 64 MiB raw
	if len(bomb) > 10000 {
		t.Fatalf("bomb not small: %d", len(bomb))
	}
	text := []byte(strings.Repeat("hello ", 1000))
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"unknown ctype 3", inner(3, 0, 1, []byte("x")), ErrUnknownCType},
		{"unknown ctype 0", inner(0, 0, 1, []byte("x")), ErrUnknownCType},
		{"unknown comp", inner(1, 7, 1, []byte("x")), ErrBadInner},
		{"huge raw_len header", inner(1, 1, 1<<40, zst([]byte("x"))), ErrTooBig},
		{"raw_len above text limit", inner(1, 1, DefaultMaxRaw+1, zst([]byte("x"))), ErrTooBig},
		{"image above image limit", inner(2, 0, DefaultMaxImage+1, nil), ErrTooBig},
		{"bomb with lying small raw_len", inner(1, 1, 1000, bomb), ErrBadInner},
		{"zstd lying raw_len larger", inner(1, 1, uint64(len(text))+10, zst(text)), ErrBadInner},
		{"zstd lying raw_len smaller", inner(1, 1, uint64(len(text))-10, zst(text)), ErrBadInner},
		{"raw lying longer", inner(1, 0, 100, []byte("short")), ErrBadInner},
		{"raw lying shorter", inner(1, 0, 2, []byte("short")), ErrBadInner},
		{"png compressed", inner(2, 1, 1, zst([]byte("x"))), ErrBadInner},
		{"short inner", []byte{1, 0, 0}, ErrBadInner},
		{"invalid utf8", inner(1, 0, 2, []byte{0xff, 0xfe}), ErrBadText},
	}
	for _, c := range cases {
		if _, err := e.open(e.rcpts[0], 0, e.sealInner(t, c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestBombStoppedByConfiguredLimit(t *testing.T) {
	e := newEnv(t, 1)
	bomb := zst(make([]byte, 64<<20))
	w := e.sealInner(t, inner(1, 1, 64<<20, bomb))
	p := e.openParams(e.rcpts[0], 0)
	p.Limits.MaxText = 1 << 20
	if _, err := OpenBytes(w, p); !errors.Is(err, ErrTooBig) {
		t.Fatal(err)
	}
}

func TestSealLimits(t *testing.T) {
	e := newEnv(t, 1)
	p := SealParams{GroupID: e.group, SenderID: e.sender.id, SigningKey: e.sender.sk, Counter: 1,
		Recipients: []age.Recipient{e.rcpts[0].ident.Recipient()}}
	if _, err := SealBytes(p, CTypeImagePNG, make([]byte, DefaultMaxImage+1)); !errors.Is(err, ErrTooBig) {
		t.Errorf("image: %v", err)
	}
	if _, err := SealBytes(p, 9, []byte("x")); !errors.Is(err, ErrUnknownCType) {
		t.Errorf("ctype: %v", err)
	}
	if _, err := SealBytes(p, CTypeText, []byte{0xff}); !errors.Is(err, ErrBadText) {
		t.Errorf("utf8: %v", err)
	}
	p.Recipients = nil
	if _, err := SealBytes(p, CTypeText, []byte("x")); err == nil {
		t.Error("no recipients accepted")
	}
}

func FuzzOpen(f *testing.F) {
	e := newEnv(f, 1)
	f.Add(e.seal(f, 1, CTypeText, []byte(strings.Repeat("fuzz ", 40))))
	f.Add(e.seal(f, 1, CTypeImagePNG, []byte("\x89PNGxxxx")))
	f.Add([]byte("ECB1"))
	p := e.openParams(e.rcpts[0], 0)
	p.Limits = Limits{MaxCiphertext: 1 << 16}
	f.Fuzz(func(t *testing.T, in []byte) {
		it, err := OpenBytes(in, p)
		if err == nil && it == nil {
			t.Fatal("nil item without error")
		}
	})
}

func benchBody() []byte {
	var b strings.Builder
	for b.Len() < 1<<20 {
		fmt.Fprintf(&b, "row %d, value %x, some typical clipboard text content\n", b.Len(), b.Len()*2654435761)
	}
	return []byte(b.String()[:1<<20])
}

func BenchmarkSeal1MiBText(b *testing.B) {
	e := newEnv(b, 3)
	body := benchBody()
	var rs []age.Recipient
	for _, r := range e.rcpts {
		rs = append(rs, r.ident.Recipient())
	}
	p := SealParams{GroupID: e.group, SenderID: e.sender.id, SigningKey: e.sender.sk, Recipients: rs, Counter: 1}
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := SealBytes(p, CTypeText, body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen1MiBText(b *testing.B) {
	e := newEnv(b, 3)
	body := benchBody()
	w := e.seal(b, 1, CTypeText, body)
	p := e.openParams(e.rcpts[2], 0)
	p.Now = func() time.Time { return e.now }
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := OpenBytes(w, p); err != nil {
			b.Fatal(err)
		}
	}
}
