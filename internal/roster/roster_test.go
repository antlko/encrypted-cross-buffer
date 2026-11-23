package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"filippo.io/age"
)

type dev struct {
	sk    ed25519.PrivateKey
	ident *age.X25519Identity
	entry Entry
}

func newDev(t testing.TB, name string) *dev {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return &dev{sk: sk, ident: id, entry: NewEntry(name, id.Recipient().String(), pk, 1000)}
}

var group = [16]byte{1, 2, 3}

func genesis(t testing.TB, d *dev) *Roster {
	t.Helper()
	r, err := NewGenesis(group, d.entry, d.sk)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func addSigned(t testing.TB, held *Roster, signer, nd *dev) *Roster {
	t.Helper()
	r, err := held.Add(signer.entry.DeviceID, nd.entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Sign(signer.sk); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGenesis(t *testing.T) {
	a := newDev(t, "a")
	r := genesis(t, a)
	if err := r.Verify(nil); err != nil {
		t.Fatal(err)
	}
	if r.Version != 1 || len(r.Entries) != 1 || r.Signer != a.entry.DeviceID {
		t.Fatalf("%+v", r)
	}
	// Genesis signed by someone else is rejected.
	b := newDev(t, "b")
	bad := &Roster{GroupID: group, Version: 1, Entries: []Entry{a.entry}}
	bad.Entries[0].AddedBy = a.entry.DeviceID
	if err := bad.Sign(b.sk); err != nil {
		t.Fatal(err)
	}
	if err := bad.Verify(nil); err == nil {
		t.Fatal("foreign genesis accepted")
	}
	// Non-genesis without held roster rejected.
	r2 := addSigned(t, r, a, b)
	if err := r2.Verify(nil); !errors.Is(err, ErrNeedGenesis) {
		t.Fatalf("got %v", err)
	}
}

func TestAddRemoveChain(t *testing.T) {
	a, b, c := newDev(t, "a"), newDev(t, "b"), newDev(t, "c")
	r1 := genesis(t, a)
	r2 := addSigned(t, r1, a, b)
	if err := r2.Verify(r1); err != nil {
		t.Fatal(err)
	}
	r3 := addSigned(t, r2, b, c) // b may sign: member of held r2
	if err := r3.Verify(r2); err != nil {
		t.Fatal(err)
	}
	if len(r3.Entries) != 3 || r3.Version != 3 {
		t.Fatal("bad r3")
	}
	r4, err := r3.Remove(b.entry.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := r4.Sign(a.sk); err != nil {
		t.Fatal(err)
	}
	if err := r4.Verify(r3); err != nil {
		t.Fatal(err)
	}
	if _, ok := r4.Lookup(b.entry.DeviceID); ok {
		t.Fatal("b still present")
	}
	// Removed device cannot sign the next version.
	r5, _ := r4.Add(b.entry.DeviceID, newDev(t, "d").entry)
	if err := r5.Sign(b.sk); err != nil {
		t.Fatal(err)
	}
	if err := r5.Verify(r4); !errors.Is(err, ErrSignerNotHeld) {
		t.Fatalf("removed signer: %v", err)
	}
	// A skipped version is fine as long as the signer is in the held roster.
	r6 := addSigned(t, r4, a, newDev(t, "e"))
	r7 := addSigned(t, r6, a, newDev(t, "f"))
	if err := r7.Verify(r4); err != nil {
		t.Fatalf("gap: %v", err)
	}
}

func TestRollbackAndGroup(t *testing.T) {
	a, b := newDev(t, "a"), newDev(t, "b")
	r1 := genesis(t, a)
	r2 := addSigned(t, r1, a, b)
	if err := r1.Verify(r2); !errors.Is(err, ErrRollback) {
		t.Fatalf("older: %v", err)
	}
	if err := r2.Verify(r2); !errors.Is(err, ErrRollback) {
		t.Fatalf("same: %v", err)
	}
	other := genesis(t, a)
	other.GroupID[0] ^= 1
	other.Sign(a.sk)
	o2 := addSigned(t, other, a, b)
	if err := o2.Verify(r1); !errors.Is(err, ErrGroupMismatch) {
		t.Fatalf("group: %v", err)
	}
}

func TestTamperedRejected(t *testing.T) {
	a, b := newDev(t, "a"), newDev(t, "b")
	r1 := genesis(t, a)
	r2 := addSigned(t, r1, a, b)
	m, err := r2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for i := range m {
		c := append([]byte(nil), m...)
		c[i] ^= 1
		got, err := Unmarshal(c)
		if err != nil {
			continue
		}
		if got.Verify(r1) == nil {
			t.Fatalf("flip at byte %d accepted", i)
		}
	}
	// Semantic tampering: swap a key for the attacker's but keep the signature.
	atk := newDev(t, "atk")
	tam, _ := Unmarshal(m)
	tam.Entries[0] = atk.entry
	tam.Entries[0].AddedBy = a.entry.DeviceID
	sortEntries(tam.Entries)
	if tam.Verify(r1) == nil {
		t.Fatal("swapped entry accepted")
	}
	// Entry with mismatched device id.
	bad := newDev(t, "bad")
	bad.entry.DeviceID[0] ^= 1
	if _, err := r1.Add(a.entry.DeviceID, bad.entry); err == nil {
		t.Fatal("device id mismatch accepted")
	}
	// New device not credited to the signer.
	r3, _ := r1.Add(b.entry.DeviceID, newDev(t, "x").entry)
	r3.Sign(a.sk)
	if err := r3.Verify(r1); err == nil {
		t.Fatal("wrong added_by accepted")
	}
}

func TestStructuralRules(t *testing.T) {
	a := newDev(t, "a")
	r := genesis(t, a)
	if _, err := r.Add(a.entry.DeviceID, a.entry); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := r.Remove(a.entry.DeviceID); err == nil {
		t.Error("empty roster accepted")
	}
	if _, err := r.Remove([16]byte{9}); err == nil {
		t.Error("remove unknown accepted")
	}
	cur := r
	for i := 1; i < MaxDevices; i++ {
		cur = addSigned(t, cur, a, newDev(t, fmt.Sprint("d", i)))
	}
	if len(cur.Entries) != MaxDevices {
		t.Fatal(len(cur.Entries))
	}
	if _, err := cur.Add(a.entry.DeviceID, newDev(t, "over").entry); err == nil {
		t.Error(">64 accepted")
	}
	dup := &Roster{GroupID: group, Version: 1, Entries: []Entry{a.entry, a.entry}}
	if err := dup.Sign(a.sk); err == nil {
		t.Error("dup signed")
	}
	e := a.entry
	e.Name = ""
	if err := (&Roster{GroupID: group, Version: 1, Entries: []Entry{e}}).Sign(a.sk); err == nil {
		t.Error("empty name accepted")
	}
}

func TestMarshalDeterministicAndStrict(t *testing.T) {
	a, b := newDev(t, "a"), newDev(t, "b")
	r := addSigned(t, genesis(t, a), a, b)
	m1, _ := r.Marshal()
	got, err := Unmarshal(m1)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := got.Marshal()
	if !bytes.Equal(m1, m2) {
		t.Fatal("not deterministic")
	}
	r.Entries[0], r.Entries[1] = r.Entries[1], r.Entries[0]
	m3, _ := r.Marshal()
	if !bytes.Equal(m1, m3) {
		t.Fatal("order-dependent encoding")
	}
	if _, err := Unmarshal(append(append([]byte(nil), m1...), 0)); err == nil {
		t.Error("trailing accepted")
	}
	for n := 0; n < len(m1); n += 7 {
		if _, err := Unmarshal(m1[:n]); err == nil {
			t.Errorf("truncated %d accepted", n)
		}
	}
	if _, err := (&Roster{}).Marshal(); err == nil {
		t.Error("unsigned marshal accepted")
	}
}

func TestSealOpen(t *testing.T) {
	a, b, out := newDev(t, "a"), newDev(t, "b"), newDev(t, "out")
	r1 := genesis(t, a)
	r := addSigned(t, r1, a, b)
	blob, err := r.Seal()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []*dev{a, b} {
		got, err := Open(blob, d.ident)
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Verify(r1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(blob, out.ident); err == nil {
		t.Fatal("outsider opened roster")
	}
	if bytes.Contains(blob, []byte("ECBR")) {
		t.Error("blob leaks plaintext structure")
	}
}

func FuzzUnmarshal(f *testing.F) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := age.GenerateX25519Identity()
	r, _ := NewGenesis(group, NewEntry("a", id.Recipient().String(), pk, 1), sk)
	m, _ := r.Marshal()
	f.Add(m)
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := Unmarshal(in)
		if err != nil {
			return
		}
		out, err := got.Marshal()
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("non-canonical accepted: %v", err)
		}
	})
}

func TestRetainedEntriesImmutable(t *testing.T) {
	a, b, c := newDev(t, "a"), newDev(t, "b"), newDev(t, "c")
	r1 := genesis(t, a)
	r2 := addSigned(t, r1, a, b)

	// Signer swaps another member's X25519 key while adding c.
	evil := newDev(t, "evil")
	mod := func(f func(e *Entry)) *Roster {
		r3, err := r2.Add(a.entry.DeviceID, c.entry)
		if err != nil {
			t.Fatal(err)
		}
		for i := range r3.Entries {
			if r3.Entries[i].DeviceID == b.entry.DeviceID {
				f(&r3.Entries[i])
			}
		}
		if err := r3.Sign(a.sk); err != nil {
			t.Fatal(err)
		}
		return r3
	}
	if err := mod(func(e *Entry) {}).Verify(r2); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string]func(e *Entry){
		"x25519":  func(e *Entry) { e.X25519Pub = evil.entry.X25519Pub },
		"rename":  func(e *Entry) { e.Name = "renamed" },
		"addedby": func(e *Entry) { e.AddedBy = b.entry.DeviceID },
		"addedat": func(e *Entry) { e.AddedAtMs++ },
	}
	for name, f := range cases {
		if err := mod(f).Verify(r2); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
