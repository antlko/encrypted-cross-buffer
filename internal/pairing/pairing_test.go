package pairing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/schollz/pake/v3"

	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
	"github.com/antlko/encrypted-cross-buffer/internal/roster"
)

type setup struct {
	fake      *fakeMailbox
	self      *keystore.Identity
	joinID    *keystore.Identity
	r         *roster.Roster
	code      Code
	published []*roster.Roster
	mu        sync.Mutex
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	self, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	jid, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	gid := [16]byte{1, 2, 3}
	r, err := roster.NewGenesis(gid, roster.NewEntry("laptop", self.Recipient(), self.PublicKey(), 1), self.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	code, err := NewCode(7, "")
	if err != nil {
		t.Fatal(err)
	}
	return &setup{fake: newFake(), self: self, joinID: jid, r: r, code: code}
}

func (s *setup) inviter() *Inviter {
	return &Inviter{
		MB: s.fake, Self: s.self, Roster: s.r, RelayURL: "http://relay.invalid",
		Publish: func(_ context.Context, r *roster.Roster) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.published = append(s.published, r)
			return nil
		},
		Timeout: 5 * time.Second, PollWait: 200 * time.Millisecond,
	}
}

func (s *setup) joiner(name string) *Joiner {
	return &Joiner{MB: s.fake, Self: s.joinID, Name: name, Timeout: 5 * time.Second, PollWait: 200 * time.Millisecond}
}

func (s *setup) publishedCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.published) }

// run runs both sides concurrently with joinCode for the joiner.
func (s *setup) run(t *testing.T, name string, joinCode Code) (*InviteResult, error, *Joined, error) {
	t.Helper()
	var (
		res  *InviteResult
		jres *Joined
		ae   error
		be   error
		wg   sync.WaitGroup
	)
	wg.Add(2)
	go func() { defer wg.Done(); res, ae = s.inviter().Run(context.Background(), s.code) }()
	go func() { defer wg.Done(); jres, be = s.joiner(name).Run(context.Background(), joinCode) }()
	wg.Wait()
	return res, ae, jres, be
}

func TestSuccess(t *testing.T) {
	s := newSetup(t)
	res, ae, jres, be := s.run(t, "phone", s.code)
	if ae != nil || be != nil {
		t.Fatalf("inviter=%v joiner=%v", ae, be)
	}
	if res.Roster.Version != 2 || len(res.Roster.Entries) != 2 || s.publishedCount() != 1 {
		t.Fatal("unexpected roster")
	}
	if jres.Roster.Version != 2 || jres.GroupID != s.r.GroupID || jres.RelayURL != "http://relay.invalid" {
		t.Fatal("joiner result mismatch")
	}
	if !s.fake.isBurned() {
		t.Fatal("mailbox must be burned after success")
	}
	// The new roster verifies against the inviter's held roster.
	if err := res.Roster.Verify(s.r); err != nil {
		t.Fatal(err)
	}
	if res.Added.Name != "phone" {
		t.Fatalf("added = %q", res.Added.Name)
	}
}

func TestWrongCode(t *testing.T) {
	s := newSetup(t)
	wrong := Code{Mailbox: s.code.Mailbox, Secret: "wrong-wrong-wrong"}
	_, ae, _, be := s.run(t, "phone", wrong)
	if ae == nil || be == nil {
		t.Fatalf("both must fail: inviter=%v joiner=%v", ae, be)
	}
	if !errors.Is(be, ErrConfirmation) {
		t.Fatalf("joiner error = %v, want ErrConfirmation", be)
	}
	if s.publishedCount() != 0 {
		t.Fatal("roster must not be published")
	}
	if !s.fake.isBurned() {
		t.Fatal("mailbox must be burned")
	}
	// The right code cannot be used afterwards: one attempt per mailbox.
	_, err := s.joiner("phone").Run(context.Background(), s.code)
	if err == nil {
		t.Fatal("second attempt on a burned mailbox must fail")
	}
}

func TestSecondJoinWithSameCodeFails(t *testing.T) {
	s := newSetup(t)
	if _, ae, _, be := s.run(t, "phone", s.code); ae != nil || be != nil {
		t.Fatal(ae, be)
	}
	j2, _ := keystore.Generate()
	jr := &Joiner{MB: s.fake, Self: j2, Name: "tablet", Timeout: time.Second, PollWait: 100 * time.Millisecond}
	if _, err := jr.Run(context.Background(), s.code); err == nil {
		t.Fatal("second join with the same code must fail")
	}
	if s.publishedCount() != 1 {
		t.Fatal("only one roster publication expected")
	}
}

func flip(b []byte) []byte {
	c := append([]byte(nil), b...)
	c[len(c)/2] ^= 0x01
	return c
}

// A malicious relay modifies each message in turn; pairing must fail, and for
// every message before the roster is released nothing may be published.
func TestRelayFlipsBitInAnyMessage(t *testing.T) {
	type pt struct {
		to      string
		n       int
		name    string
		publish bool // may the roster already be published when this one is hit?
	}
	points := []pt{
		{"b", 0, "msg1", false}, {"a", 0, "msg2", false}, {"b", 1, "confA", false},
		{"a", 1, "confB", false}, {"a", 2, "descriptor", false}, {"b", 2, "roster", true}, {"a", 3, "done", true},
	}
	for _, p := range points {
		t.Run(p.name, func(t *testing.T) {
			s := newSetup(t)
			s.fake.Tamper = func(to string, n int, data []byte, _ [][]byte) [][]byte {
				if to == p.to && n == p.n {
					return [][]byte{flip(data)}
				}
				return [][]byte{data}
			}
			_, ae, _, be := s.run(t, "phone", s.code)
			if ae == nil && be == nil {
				t.Fatal("tampering went unnoticed")
			}
			if !p.publish && s.publishedCount() != 0 {
				t.Fatal("roster published despite tampering")
			}
			if !s.fake.isBurned() {
				t.Fatal("mailbox must be burned")
			}
		})
	}
}

func TestRelayReplaySwapReflect(t *testing.T) {
	cases := map[string]func(to string, n int, data []byte, all [][]byte) [][]byte{
		// replay msg2 where confB is expected
		"replay-msg2-as-confB": func(to string, n int, data []byte, all [][]byte) [][]byte {
			if to == "a" && n == 1 {
				return [][]byte{all[1]}
			}
			return [][]byte{data}
		},
		// reflect A's own confirmation back to A as B's
		"reflect-confA": func(to string, n int, data []byte, all [][]byte) [][]byte {
			if to == "a" && n == 1 {
				return [][]byte{all[2]}
			}
			return [][]byte{data}
		},
		// reorder: deliver desc before confB
		"reorder": func(to string, n int, data []byte, all [][]byte) [][]byte {
			if to == "a" && n == 1 {
				return nil // hold confB back...
			}
			if to == "a" && n == 2 {
				return [][]byte{data, all[len(all)-1]} // ...and deliver desc first, then confB
			}
			return [][]byte{data}
		},
		// descriptor replayed as the roster message
		"desc-as-roster": func(to string, n int, data []byte, all [][]byte) [][]byte {
			if to == "b" && n == 2 {
				return [][]byte{all[len(all)-1]}
			}
			return [][]byte{data}
		},
		// drop the roster
		"drop-roster": func(to string, n int, data []byte, all [][]byte) [][]byte {
			if to == "b" && n == 2 {
				return nil
			}
			return [][]byte{data}
		},
	}
	for name, tam := range cases {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			s.fake.Tamper = tam
			// Shorten: dropped messages must time out quickly.
			ia, jb := s.inviter(), s.joiner("phone")
			ia.Timeout, jb.Timeout = 1500*time.Millisecond, 1500*time.Millisecond
			var ae, be error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _, ae = ia.Run(context.Background(), s.code) }()
			go func() { defer wg.Done(); _, be = jb.Run(context.Background(), s.code) }()
			wg.Wait()
			if ae == nil && be == nil {
				t.Fatal("attack went unnoticed")
			}
			if name != "drop-roster" && name != "desc-as-roster" && s.publishedCount() != 0 {
				t.Fatal("roster published despite attack")
			}
			if !s.fake.isBurned() {
				t.Fatal("mailbox must be burned")
			}
		})
	}
}

// The relay replaces both PAKE messages with ones from its own sessions.
func TestRelaySubstitutesOwnPake(t *testing.T) {
	s := newSetup(t)
	evil := Code{Mailbox: s.code.Mailbox, Secret: "guess-guess-guess"}
	id := []byte("ecb-pair-v1|7")
	ea, _ := pake.InitCurveWithIdentities([]byte(evil.String()), 0, curve, id, id)
	eb, _ := pake.InitCurveWithIdentities([]byte(evil.String()), 1, curve, id, id)
	s.fake.Tamper = func(to string, n int, data []byte, _ [][]byte) [][]byte {
		if to == "b" && n == 0 {
			return [][]byte{ea.Bytes()}
		}
		if to == "a" && n == 0 {
			return [][]byte{eb.Bytes()}
		}
		return [][]byte{data}
	}
	_, ae, _, be := s.run(t, "phone", s.code)
	if ae == nil || be == nil {
		t.Fatalf("both must fail: %v / %v", ae, be)
	}
	if s.publishedCount() != 0 {
		t.Fatal("roster published")
	}
}

func TestRejectedDescriptors(t *testing.T) {
	long := strings.Repeat("x", 65)
	for name, jname := range map[string]string{"empty": "", "too-long": long, "duplicate-name": "laptop", "control": "a\x00b",
		"zero-width": "ph\u200bone", "bidi-override": "a\u202eb", "private-use": "ph\ue000one", "nbsp": "ph\u00a0one",
		"case-duplicate": "LAPTOP", "space-duplicate": "lap top", "mark-duplicate": "l\u0301aptop" + "", "only-spaces": " "} {
		t.Run(name, func(t *testing.T) {
			s := newSetup(t)
			_, ae, _, be := s.run(t, jname, s.code)
			if ae == nil || be == nil {
				t.Fatalf("must fail: %v / %v", ae, be)
			}
			if s.publishedCount() != 0 {
				t.Fatal("published")
			}
		})
	}
	t.Run("device-already-present", func(t *testing.T) {
		s := newSetup(t)
		s.joinID = s.self // same keys as the inviter
		_, ae, _, _ := s.run(t, "other", s.code)
		if !errors.Is(ae, ErrRejected) || s.publishedCount() != 0 {
			t.Fatalf("err=%v", ae)
		}
	})
}

func TestDeviceCap(t *testing.T) {
	s := newSetup(t)
	r := s.r
	for i := 1; i < roster.MaxDevices; i++ {
		id, _ := keystore.Generate()
		var err error
		r, err = r.Add(s.self.DeviceID(), roster.NewEntry("d"+strings.Repeat("a", i%5)+string(rune('A'+i%26))+string(rune('a'+i/26)), id.Recipient(), id.PublicKey(), 1))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Sign(s.self.Ed25519); err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != roster.MaxDevices {
		t.Fatalf("entries = %d", len(r.Entries))
	}
	s.r = r
	_, ae, _, be := s.run(t, "one-too-many", s.code)
	if !errors.Is(ae, ErrRejected) || be == nil || s.publishedCount() != 0 {
		t.Fatalf("inviter=%v joiner=%v", ae, be)
	}
}

func TestTimeout(t *testing.T) {
	s := newSetup(t)
	in := s.inviter()
	in.Timeout = 300 * time.Millisecond
	_, err := in.Run(context.Background(), s.code)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if !s.fake.isBurned() || s.publishedCount() != 0 {
		t.Fatal("must burn and not publish")
	}
	// Joiner side: no inviter at all.
	s2 := newSetup(t)
	jr := s2.joiner("phone")
	jr.Timeout = 300 * time.Millisecond
	if _, err := jr.Run(context.Background(), s2.code); !errors.Is(err, ErrTimeout) || !s2.fake.isBurned() {
		t.Fatalf("joiner err = %v", err)
	}
}

// Verify(nil) only accepts a v1 single-member genesis, but a joiner always
// receives v>=2. The bootstrap check is acceptable only because the roster
// came through the authenticated PAKE channel; it still checks the signature.
func TestBootstrapRosterVerification(t *testing.T) {
	s := newSetup(t)
	e := roster.NewEntry("phone", s.joinID.Recipient(), s.joinID.PublicKey(), 2)
	r2, _ := s.r.Add(s.self.DeviceID(), e)
	if err := r2.Sign(s.self.Ed25519); err != nil {
		t.Fatal(err)
	}
	if err := r2.Verify(nil); err == nil {
		t.Fatal("precondition: Verify(nil) is expected to reject v2")
	}
	if err := verifyBootstrapRoster(r2); err != nil {
		t.Fatal(err)
	}
	// Signed by a key that is not the claimed signer's.
	bad := *r2
	bad.Sig = append([]byte(nil), r2.Sig...)
	bad.Sig[0] ^= 1
	if err := verifyBootstrapRoster(&bad); err == nil {
		t.Fatal("bad signature accepted")
	}
	// Signer not a member of the roster.
	stranger, _ := keystore.Generate()
	r3, _ := s.r.Add(s.self.DeviceID(), e)
	_ = r3.Sign(stranger.Ed25519)
	if err := verifyBootstrapRoster(r3); err == nil {
		t.Fatal("non-member signer accepted")
	}
	// Genesis (v1) is not a valid joiner roster.
	if err := verifyBootstrapRoster(s.r); err == nil {
		t.Fatal("v1 accepted")
	}
	_ = ed25519.PublicKeySize
}

func TestJoinerChecksOwnEntryAndGroup(t *testing.T) {
	s := newSetup(t)
	other, _ := keystore.Generate()
	r2, _ := s.r.Add(s.self.DeviceID(), roster.NewEntry("someoneelse", other.Recipient(), other.PublicKey(), 2))
	_ = r2.Sign(s.self.Ed25519)
	rb, _ := r2.Marshal()
	msg := append(append(append([]byte(nil), r2.GroupID[:]...), 0, 0), rb...)
	if _, err := s.joiner("phone").parseRoster(msg); !errors.Is(err, ErrRejected) {
		t.Fatalf("roster without own entry accepted: %v", err)
	}
	// group id mismatch
	e := roster.NewEntry("phone", s.joinID.Recipient(), s.joinID.PublicKey(), 2)
	r3, _ := s.r.Add(s.self.DeviceID(), e)
	_ = r3.Sign(s.self.Ed25519)
	rb3, _ := r3.Marshal()
	gid := r3.GroupID
	gid[0] ^= 1
	msg = append(append(append([]byte(nil), gid[:]...), 0, 0), rb3...)
	if _, err := s.joiner("phone").parseRoster(msg); !errors.Is(err, ErrRejected) {
		t.Fatalf("group id mismatch accepted: %v", err)
	}
	// correct
	msg = append(append(append([]byte(nil), r3.GroupID[:]...), 0, 0), rb3...)
	if _, err := s.joiner("phone").parseRoster(msg); err != nil {
		t.Fatal(err)
	}
}

func TestPakeUpdateOnce(t *testing.T) {
	c := Code{1, "aaaa-bbbb-cccc"}
	a, _ := newPake(c, roleA)
	b, _ := newPake(c, roleB)
	if err := b.update(a.bytes()); err != nil {
		t.Fatal(err)
	}
	if err := b.update(a.bytes()); err == nil {
		t.Fatal("second update must fail")
	}
	if err := a.update([]byte("garbage")); err == nil {
		t.Fatal("garbage must fail without panicking")
	}
}

func TestCodeParsing(t *testing.T) {
	c, err := ParseCode("  7-Orbit-Velvet-Candle ")
	if err != nil || c.Mailbox != 7 || c.String() != "7-orbit-velvet-candle" {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []string{"", "orbit-velvet", "0-a-b-c", "100-a-b-c", "7-", "x-y-z"} {
		if _, err := ParseCode(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := NewCode(5, "short"); err == nil {
		t.Fatal("short secret accepted")
	}
	g, _ := NewCode(5, "")
	if len(strings.Split(g.Secret, "-")) != 3 {
		t.Fatal(g.Secret)
	}
	if SecretWarning("abcdefgh") == "" || SecretWarning("a-much-longer-secret") != "" {
		t.Fatal("warning logic")
	}
}
