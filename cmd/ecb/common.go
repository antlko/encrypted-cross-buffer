package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

// newFlagSet returns a FlagSet that prints its help to stdout and returns
// flag.ErrHelp instead of exiting.
func newFlagSet(name, desc string) *flag.FlagSet {
	fs := flag.NewFlagSet("ecb "+name, flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options]\n\n%s\n\nOptions:\n", fs.Name(), desc)
		fs.PrintDefaults()
	}
	return fs
}

// parseInterspersed parses flags that may appear before or after positional
// arguments (the stdlib stops at the first positional).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// nullKeyring makes the "file" keystore backend never touch the OS keychain
// (the keystore would otherwise try to delete a stale keychain entry).
type nullKeyring struct{}

func (nullKeyring) Get() (string, error) { return "", keystore.ErrNotFound }
func (nullKeyring) Set(string) error     { return errors.New("keychain disabled (ECB_KEYSTORE=file)") }
func (nullKeyring) Delete() error        { return nil }

func openStore(allowFile bool) (*keystore.Store, error) {
	o := keystore.Options{Dir: os.Getenv("ECB_CONFIG_DIR"), AllowFileFallback: allowFile}
	if strings.EqualFold(strings.TrimSpace(os.Getenv(keystore.EnvBackend)), "file") {
		o.Keyring = nullKeyring{}
	}
	return keystore.Open(o)
}

// local is a set-up device: identity, state, verified roster.
type local struct {
	store *keystore.Store
	id    *keystore.Identity
	state *keystore.State
	ros   *roster.Roster
}

func loadLocal(store *keystore.Store) (*local, error) {
	id, err := store.LoadIdentity()
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, errors.New("this device is not set up: run `ecb init` (first device) or `ecb join` (additional device)")
		}
		return nil, err
	}
	st, err := store.LoadState()
	if err != nil {
		return nil, err
	}
	if st.RelayURL == "" || len(st.RosterBlob) == 0 {
		return nil, errors.New("this device is not part of a group yet: run `ecb init` or `ecb join`")
	}
	r, err := roster.Open(st.RosterBlob, id.X25519)
	if err != nil {
		return nil, errors.New("cannot read the stored roster with this device's key")
	}
	return &local{store: store, id: id, state: st, ros: r}, nil
}

func (l *local) client() (*client.Client, error) {
	return client.New(client.Config{
		BaseURL: l.state.RelayURL, Identity: l.id, GroupID: l.state.GroupID,
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return l.ros, nil }),
		State:  l.state, Store: l.store,
	})
}

// saveRoster stores r (sealed to its members) as the local roster.
func (l *local) saveRoster(r *roster.Roster) error {
	blob, err := r.Seal()
	if err != nil {
		return err
	}
	if err := l.store.UpdateState(func(s *keystore.State) error { s.RosterBlob = blob; return nil }); err != nil {
		return err
	}
	l.ros, l.state.RosterBlob = r, blob
	return nil
}

// syncRoster fetches the relay's roster and, if newer, verifies it against the
// held one and stores it.
func (l *local) syncRoster(ctx context.Context, cl *client.Client) error {
	info, err := cl.FetchRoster(ctx)
	if err != nil {
		return err
	}
	if info.Roster.Version <= l.ros.Version {
		return nil
	}
	if err := info.Roster.Verify(l.ros); err != nil {
		return fmt.Errorf("the relay returned a roster that does not verify (%v); refusing it", err)
	}
	if _, ok := info.Roster.Lookup(l.id.DeviceID()); !ok {
		return errors.New("this device has been removed from the group")
	}
	return l.saveRoster(info.Roster)
}

func friendlyNet(err error, relayURL string) error {
	if client.IsStatus(err, 401) || client.IsStatus(err, 403) {
		return fmt.Errorf("the relay refused this device (it may have been removed from the group): %w", err)
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		return err
	}
	return fmt.Errorf("cannot reach the relay at %s: %w", relayURL, err)
}

func normaliseRelay(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", usagef("--relay must be an http(s) URL such as https://ecb.example.com")
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			fmt.Fprintln(errw, "WARNING: the relay URL is plain http. Clipboard items stay encrypted, but device auth and metadata are visible on the network. Use https.")
		}
	}
	return s, nil
}

func randomGroupID() ([16]byte, error) {
	var g [16]byte
	_, err := rand.Read(g[:])
	return g, err
}

func hostnameOr(def string) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		if i := strings.IndexByte(h, '.'); i > 0 {
			h = h[:i]
		}
		if len(h) > roster.MaxNameLen {
			h = h[:roster.MaxNameLen]
		}
		return h
	}
	return def
}

func shortID(id [16]byte) string { return fmt.Sprintf("%x", id[:4]) }

func ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
