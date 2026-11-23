// Package clip is the clipboard abstraction used by the daemon.
//
// Two implementations exist: the OS clipboard (golang.design/x/clipboard,
// cgo-free) and a file-backed fake used ONLY by tests and the CLI end-to-end
// script, selected by the environment variable ECB_CLIPBOARD_BACKEND=file:<dir>.
package clip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Kind is the clipboard content kind.
type Kind uint8

// Supported kinds. Nothing else is ever synced (ADR-011).
const (
	KindText Kind = 1 // UTF-8 text
	KindPNG  Kind = 2 // PNG image, bytes unchanged
)

func (k Kind) String() string {
	switch k {
	case KindText:
		return "text"
	case KindPNG:
		return "png"
	}
	return "unknown"
}

// PNGSignature is the 8-byte PNG file signature.
var PNGSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// Event is a local clipboard change.
type Event struct {
	Kind Kind
	Data []byte
	// Sensitive is set when the copying application marked the content as
	// sensitive (password managers). Such items must never be synced.
	Sensitive bool
}

// Clipboard is a readable, writable and watchable clipboard.
type Clipboard interface {
	Read(ctx context.Context, k Kind) ([]byte, error)
	Write(ctx context.Context, k Kind, data []byte) error
	// Watch emits every change until ctx ends, then closes the channel.
	Watch(ctx context.Context) <-chan Event
}

// EnvBackend selects the TEST-ONLY file backend: ECB_CLIPBOARD_BACKEND=file:<dir>.
// Never set it in normal use.
const EnvBackend = "ECB_CLIPBOARD_BACKEND"

// ErrNoData means the clipboard holds nothing of the requested kind.
var ErrNoData = errors.New("clip: no data")

// New returns the clipboard selected by the environment: the file fake when
// ECB_CLIPBOARD_BACKEND=file:<dir>, otherwise the OS clipboard.
func New() (Clipboard, error) {
	if v := os.Getenv(EnvBackend); v != "" {
		dir, ok := strings.CutPrefix(v, "file:")
		if !ok || dir == "" {
			return nil, fmt.Errorf("clip: %s must look like file:<dir>", EnvBackend)
		}
		return NewFile(dir)
	}
	return NewSystem()
}
