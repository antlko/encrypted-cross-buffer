package relay

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type itemMeta struct {
	id      string
	size    int64
	from    string
	created time.Time
	path    string
}

// spool keeps the latest item per group as a file under dir/<gid>/<id>.
// Item metadata is in memory only: leftovers from a previous run are wiped at
// start (items are short-lived by design).
type spool struct {
	dir    string
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	latest map[string]*itemMeta
}

func newSpool(dataDir string, ttl time.Duration, now func() time.Time) (*spool, error) {
	dir := filepath.Join(dataDir, "items")
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &spool{dir: dir, ttl: ttl, now: now, latest: map[string]*itemMeta{}}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newTemp creates a 0600 temp file in the group's spool dir (0700).
func (sp *spool) newTemp(gid string) (*os.File, error) {
	d := filepath.Join(sp.dir, gid)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(d, "tmp-"+randHex(8)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}

// commit renames tmp to the group's new latest item and deletes the previous.
func (sp *spool) commit(gid, tmp, from string, size int64) (*itemMeta, error) {
	id := randHex(16)
	final := filepath.Join(sp.dir, gid, id)
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if err := os.Rename(tmp, final); err != nil {
		return nil, err
	}
	if old := sp.latest[gid]; old != nil {
		_ = os.Remove(old.path)
	}
	m := &itemMeta{id: id, size: size, from: from, created: sp.now(), path: final}
	sp.latest[gid] = m
	return m, nil
}

// open returns the group's latest item if it has this id and has not expired.
func (sp *spool) open(gid, id string) (*os.File, *itemMeta) {
	sp.mu.Lock()
	m := sp.latest[gid]
	if m == nil || m.id != id {
		sp.mu.Unlock()
		return nil, nil
	}
	if sp.now().Sub(m.created) > sp.ttl {
		_ = os.Remove(m.path)
		delete(sp.latest, gid)
		sp.mu.Unlock()
		return nil, nil
	}
	sp.mu.Unlock()
	f, err := os.Open(m.path)
	if err != nil {
		return nil, nil
	}
	return f, m
}

func (sp *spool) sweep() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for gid, m := range sp.latest {
		if sp.now().Sub(m.created) > sp.ttl {
			_ = os.Remove(m.path)
			delete(sp.latest, gid)
		}
	}
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
