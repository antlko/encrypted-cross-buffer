package relay

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigFromEnv(t *testing.T) {
	tok := "0123456789abcdef"
	c, err := ConfigFromEnv(env(map[string]string{"ECB_ENROLL_TOKEN": tok}))
	if err != nil || c.Addr != ":8080" || c.DataDir != "/data" || c.MaxItemBytes != 33554432 ||
		c.ItemTTL != 10*time.Minute || c.TrustProxyHeaders {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	c, err = ConfigFromEnv(env(map[string]string{"ECB_ENROLL_TOKEN": tok, "ECB_ADDR": ":9", "ECB_DATA_DIR": "/x",
		"ECB_MAX_ITEM_BYTES": "5000", "ECB_ITEM_TTL": "30s", "ECB_TRUST_PROXY_HEADERS": "true"}))
	if err != nil || c.Addr != ":9" || c.DataDir != "/x" || c.MaxItemBytes != 5000 || c.ItemTTL != 30*time.Second || !c.TrustProxyHeaders {
		t.Fatalf("overrides: %+v %v", c, err)
	}
	for _, bad := range []map[string]string{
		{}, {"ECB_ENROLL_TOKEN": "short-secret"},
		{"ECB_ENROLL_TOKEN": tok, "ECB_MAX_ITEM_BYTES": "x"},
		{"ECB_ENROLL_TOKEN": tok, "ECB_ITEM_TTL": "-1s"},
		{"ECB_ENROLL_TOKEN": tok, "ECB_TRUST_PROXY_HEADERS": "maybe"},
	} {
		_, err := ConfigFromEnv(env(bad))
		if err == nil {
			t.Fatalf("accepted %v", bad)
		}
		if tk := bad["ECB_ENROLL_TOKEN"]; tk != "" && strings.Contains(err.Error(), tk) {
			t.Fatalf("error leaks the token: %v", err)
		}
	}
	if _, err := New(Config{DataDir: t.TempDir(), EnrollToken: "short"}, nil); err == nil {
		t.Fatal("New accepted a short enroll token")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(Rate{Burst: 3, Every: time.Second}, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if !l.allow("k") {
			t.Fatalf("burst %d denied", i)
		}
	}
	if l.allow("k") || !l.allow("other") {
		t.Fatal("bucket isolation / exhaustion wrong")
	}
	now = now.Add(1500 * time.Millisecond)
	if !l.allow("k") || l.allow("k") {
		t.Fatal("refill wrong")
	}
	if !l.peek("other") {
		t.Fatal("peek")
	}
	now = now.Add(time.Hour)
	l.sweep()
	if len(l.m) != 0 {
		t.Fatalf("idle buckets not swept: %d", len(l.m))
	}
}

func TestWireMessagesAreDomainSeparated(t *testing.T) {
	gid := [16]byte{1}
	pub := make(ed25519.PublicKey, 32)
	k1, k2 := make(ed25519.PublicKey, 32), make(ed25519.PublicKey, 32)
	k1[0], k2[0] = 9, 3
	a := RosterPubMessage(gid, 2, []byte("b"), []ed25519.PublicKey{k1, k2})
	b := RosterPubMessage(gid, 2, []byte("b"), []ed25519.PublicKey{k2, k1})
	if string(a) != string(b) {
		t.Fatal("key order must not matter")
	}
	msgs := [][]byte{a, GroupCreateMessage(gid, pub, []byte("b"), 2), AuthMessage([]byte("n"), gid)}
	for i := range msgs {
		for j := range msgs {
			if i != j && string(msgs[i]) == string(msgs[j]) {
				t.Fatal("messages collide")
			}
		}
	}
}

func TestPairManagerClockAndLimits(t *testing.T) {
	now := time.Unix(5000, 0)
	p := newPairMgr(func() time.Time { return now })
	id, e := p.create("g")
	if e != pairOK || id < 1 || id > 99 {
		t.Fatal(id, e)
	}
	if p.post(id, "a", []byte("x")) != pairOK {
		t.Fatal("post")
	}
	now = now.Add(pairTTL + time.Second)
	if p.post(id, "a", []byte("x")) != pairGone {
		t.Fatal("expired mailbox accepted a post")
	}
	if _, gone := p.get(context.Background(), id, "a", 0); !gone {
		t.Fatal("expired mailbox readable")
	}
	// A burned id is reusable and ids stay within 1..99 when many exist.
	ids := map[int]bool{}
	for g := 0; g < 25; g++ {
		for i := 0; i < pairMaxPerGroup; i++ {
			id, e := p.create(string(rune('A' + g)))
			if e != pairOK {
				if g < 24 {
					t.Fatalf("create g=%d i=%d: %v", g, i, e)
				}
				continue
			}
			if ids[id] {
				t.Fatalf("duplicate id %d", id)
			}
			ids[id] = true
		}
	}
}

func TestIsHex(t *testing.T) {
	if !isHex("00ff", 4) || isHex("00FF", 4) || isHex("../a", 4) || isHex("00ff", 5) {
		t.Fatal("isHex")
	}
}
