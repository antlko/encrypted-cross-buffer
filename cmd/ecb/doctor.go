package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/doctor"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

func cmdDoctor(args []string) error {
	fs := newFlagSet("doctor", "Check, layer by layer, whether the relay is reachable from this network\n"+
		"(URL, DNS, TCP, TLS, HTTP, login, WebSocket, long-poll) and say WHICH layer fails.\n"+
		"Safe to run anywhere: it sends no clipboard items and prints no secrets.")
	relay := fs.String("relay", "", "relay URL (default: $ECB_RELAY, else this device's saved relay)")
	dur := fs.Duration("duration", 60*time.Second, "how long to hold the WebSocket open")
	noWS := fs.Bool("no-ws", false, "skip the WebSocket hold (faster)")
	asJSON := fs.Bool("json", false, "print a machine-readable JSON report instead of text")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usagef("%v", err)
	}
	if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	if *dur <= 0 {
		return usagef("--duration must be positive")
	}

	opts := doctor.Options{RelayURL: *relay, Duration: *dur, NoWS: *noWS}
	// A set-up device enables the login / WebSocket / long-poll steps.
	var savedURL string
	store, serr := openStore(false)
	if serr == nil {
		l, lerr := loadLocal(store)
		if lerr == nil {
			savedURL = l.state.RelayURL
			st := *l.state // doctor never changes counters; keep it off the disk store
			ros := l.ros
			opts.Client = &client.Config{
				Identity: l.id, GroupID: st.GroupID, State: &st,
				Roster: client.RosterFunc(func() (*roster.Roster, error) { return ros, nil }),
			}
		} else {
			opts.NoClientReason = lerr.Error()
		}
	} else {
		opts.NoClientReason = "cannot open the key store: " + serr.Error()
	}
	if opts.RelayURL == "" {
		opts.RelayURL = strings.TrimSpace(os.Getenv("ECB_RELAY"))
	}
	if opts.RelayURL == "" {
		opts.RelayURL = savedURL
	}
	if opts.Client != nil && !sameRelay(opts.RelayURL, savedURL) {
		opts.Client = nil
		opts.NoClientReason = "the URL being tested differs from this device's saved relay, so its login would not apply"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !*asJSON {
		fmt.Fprintf(out, "ecb doctor: checking %s\n\n", displayURL(opts.RelayURL))
		n := 0
		opts.Progress = func(s doctor.Step) {
			n++
			printStep(n, s)
		}
		opts.Note = func(s string) { fmt.Fprintf(out, "       ... %s\n", s) }
	}
	rep := doctor.Run(ctx, opts)
	if *asJSON {
		enc := json.NewEncoder(out)
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(out, "\n%s\n", rep.Summary)
	}
	if rep.Verdict == doctor.VerdictFail {
		return errors.New("connectivity check failed (see above)")
	}
	return nil
}

func sameRelay(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), "/"), strings.TrimRight(strings.TrimSpace(b), "/"))
}

// displayURL hides anything but scheme://host[:port] (no userinfo or query).
func displayURL(s string) string {
	if s == "" {
		return "(no relay URL)"
	}
	if i := strings.Index(s, "://"); i > 0 {
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if k := strings.LastIndexByte(rest, '@'); k >= 0 {
			rest = rest[k+1:]
		}
		return s[:i+3] + rest
	}
	return s
}

func printStep(n int, s doctor.Step) {
	tag := map[doctor.Status]string{doctor.OK: "[ OK ]", doctor.Warn: "[WARN]", doctor.Fail: "[FAIL]", doctor.Skip: "[SKIP]"}[s.Status]
	opt := ""
	if s.Optional {
		opt = " (optional)"
	}
	fmt.Fprintf(out, "%s %d. %s%s: %s\n", tag, n, s.ID, opt, s.Detail)
	if s.Hint != "" {
		fmt.Fprintf(out, "       what to do: %s\n", s.Hint)
	}
}
