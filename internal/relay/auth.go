package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	nonceTTL   = 60 * time.Second
	tokenTTL   = 15 * time.Minute
	maxNonces  = 20000
	maxSession = 20000
)

type session struct {
	gid string
	pub pubKey
	dev [16]byte
	exp time.Time
}

type nonceRec struct {
	gid string
	exp time.Time
}

type authState struct {
	mu       sync.Mutex
	now      func() time.Time
	nonces   map[string]nonceRec // key: base64 nonce
	sessions map[[32]byte]*session
}

func newAuthState(now func() time.Time) *authState {
	return &authState{now: now, nonces: map[string]nonceRec{}, sessions: map[[32]byte]*session{}}
}

func (a *authState) newNonce(gid string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.nonces) >= maxNonces {
		a.sweepLocked()
		if len(a.nonces) >= maxNonces {
			return "", false
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	n := base64.StdEncoding.EncodeToString(b)
	a.nonces[n] = nonceRec{gid: gid, exp: a.now().Add(nonceTTL)}
	return n, true
}

// consumeNonce atomically removes the nonce and reports whether it was valid
// for gid. A nonce is single-use even if the following verification fails.
func (a *authState) consumeNonce(n, gid string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := a.nonces[n]
	if !ok {
		return false
	}
	delete(a.nonces, n)
	return r.gid == gid && a.now().Before(r.exp)
}

func (a *authState) issue(gid string, pub pubKey) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) >= maxSession {
		a.sweepLocked()
		if len(a.sessions) >= maxSession {
			return "", false
		}
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := base64.RawURLEncoding.EncodeToString(b)
	a.sessions[sha256.Sum256([]byte(tok))] = &session{gid: gid, pub: pub, dev: pub.deviceID(), exp: a.now().Add(tokenTTL)}
	return tok, true
}

func (a *authState) lookup(tok string) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := sha256.Sum256([]byte(tok))
	s := a.sessions[k]
	if s == nil {
		return nil
	}
	if !a.now().Before(s.exp) {
		delete(a.sessions, k)
		return nil
	}
	return s
}

// revoke drops the sessions of gid whose key is not in keep.
func (a *authState) revoke(gid string, keep map[pubKey]struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if s.gid != gid {
			continue
		}
		if _, ok := keep[s.pub]; !ok {
			delete(a.sessions, k)
		}
	}
}

func (a *authState) sweep() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweepLocked()
}

func (a *authState) sweepLocked() {
	t := a.now()
	for k, n := range a.nonces {
		if !t.Before(n.exp) {
			delete(a.nonces, k)
		}
	}
	for k, s := range a.sessions {
		if !t.Before(s.exp) {
			delete(a.sessions, k)
		}
	}
}

func bearer(r *http.Request, allowQuery bool) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			return strings.TrimSpace(h[7:])
		}
		return ""
	}
	if allowQuery {
		return r.URL.Query().Get("token")
	}
	return ""
}
