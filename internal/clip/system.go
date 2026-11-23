package clip

import (
	"context"
	"errors"
	"fmt"

	"golang.design/x/clipboard"
)

type system struct{}

// NewSystem returns the OS clipboard. It fails when there is no clipboard to
// talk to (for example a Linux session without a display).
func NewSystem() (Clipboard, error) {
	if err := clipboard.Init(); err != nil {
		return nil, fmt.Errorf("clipboard unavailable: %w", err)
	}
	return system{}, nil
}

func fmtOf(k Kind) (clipboard.Format, error) {
	switch k {
	case KindText:
		return clipboard.FmtText, nil
	case KindPNG:
		return clipboard.FmtImage, nil
	}
	return 0, fmt.Errorf("clip: unsupported kind %d", k)
}

func (system) Read(ctx context.Context, k Kind) ([]byte, error) {
	f, err := fmtOf(k)
	if err != nil {
		return nil, err
	}
	b, err := clipboard.Read(ctx, f)
	if errors.Is(err, clipboard.ErrNoData) {
		return nil, ErrNoData
	}
	return b, err
}

func (system) Write(ctx context.Context, k Kind, data []byte) error {
	f, err := fmtOf(k)
	if err != nil {
		return err
	}
	_, err = clipboard.Write(ctx, f, data)
	return err
}

func (system) Watch(ctx context.Context) <-chan Event {
	out := make(chan Event, 4)
	in := clipboard.Watch(ctx)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case d, ok := <-in:
				if !ok {
					return
				}
				var k Kind
				switch d.Format {
				case clipboard.FmtText:
					k = KindText
				case clipboard.FmtImage:
					k = KindPNG
				default:
					continue
				}
				// The Sensitive flag is propagated; the daemon drops such items.
				select {
				case out <- Event{Kind: k, Data: d.Bytes, Sensitive: d.Sensitive}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}
