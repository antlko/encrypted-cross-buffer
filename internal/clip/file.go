package clip

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// fileClip is a file-backed fake clipboard (TEST ONLY): <dir>/text and
// <dir>/image.png hold the content; if <dir>/sensitive exists, events are
// flagged sensitive. Watch polls the directory every 100 ms.
type fileClip struct {
	dir  string
	poll time.Duration
}

// NewFile returns the file-backed fake. Test-only; see EnvBackend.
func NewFile(dir string) (Clipboard, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &fileClip{dir: dir, poll: 100 * time.Millisecond}, nil
}

func (f *fileClip) path(k Kind) (string, error) {
	switch k {
	case KindText:
		return filepath.Join(f.dir, "text"), nil
	case KindPNG:
		return filepath.Join(f.dir, "image.png"), nil
	}
	return "", fmt.Errorf("clip: unsupported kind %d", k)
}

func (f *fileClip) Read(_ context.Context, k Kind) ([]byte, error) {
	p, err := f.path(k)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, ErrNoData
	}
	return b, err
}

// Write replaces the content of kind k atomically.
func (f *fileClip) Write(_ context.Context, k Kind, data []byte) error {
	p, err := f.path(k)
	if err != nil {
		return err
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	tmp := filepath.Join(f.dir, ".tmp-"+hex.EncodeToString(r[:]))
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (f *fileClip) Watch(ctx context.Context) <-chan Event {
	out := make(chan Event, 4)
	last := map[Kind][]byte{}
	// Existing content at start is not a change. Snapshot it synchronously,
	// before the goroutine starts, so a copy made right after Watch returns
	// is never mistaken for the baseline.
	for _, k := range []Kind{KindText, KindPNG} {
		if b, err := f.Read(ctx, k); err == nil {
			last[k] = b
		}
	}
	go func() {
		defer close(out)
		t := time.NewTicker(f.poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			for _, k := range []Kind{KindText, KindPNG} {
				b, err := f.Read(ctx, k)
				if err != nil || bytes.Equal(b, last[k]) {
					continue
				}
				last[k] = b
				_, serr := os.Stat(filepath.Join(f.dir, "sensitive"))
				select {
				case out <- Event{Kind: k, Data: b, Sensitive: serr == nil}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}
