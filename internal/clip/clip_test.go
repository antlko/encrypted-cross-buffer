package clip

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileBackend(t *testing.T) {
	dir := t.TempDir()
	c, err := NewFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Read(ctx, KindText); err != ErrNoData {
		t.Fatalf("err = %v", err)
	}
	w := c.Watch(ctx)
	// Write through another handle (an external "copy").
	other, _ := NewFile(dir)
	if err := other.Write(ctx, KindText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-w:
		if e.Kind != KindText || string(e.Data) != "hello" || e.Sensitive {
			t.Fatalf("event %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no event")
	}
	if err := os.WriteFile(filepath.Join(dir, "sensitive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = other.Write(ctx, KindPNG, append(append([]byte(nil), PNGSignature...), 1, 2, 3))
	select {
	case e := <-w:
		if e.Kind != KindPNG || !e.Sensitive {
			t.Fatalf("event %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no png event")
	}
}

func TestNewSelectsFile(t *testing.T) {
	t.Setenv(EnvBackend, "file:"+t.TempDir())
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*fileClip); !ok {
		t.Fatalf("got %T", c)
	}
	t.Setenv(EnvBackend, "bogus")
	if _, err := New(); err == nil {
		t.Fatal("bogus backend accepted")
	}
}
