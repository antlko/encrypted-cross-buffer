package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/anatolkzh/encrypted-cross-buffer/internal/client"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/clip"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/daemon"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/keystore"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/pairing"
	"github.com/anatolkzh/encrypted-cross-buffer/internal/roster"
)

func reportBackend(store *keystore.Store) {
	if store.Backend() == "file" {
		fmt.Fprintln(errw, "")
		fmt.Fprintln(errw, "!!! WARNING: the device key is stored in a PLAINTEXT FILE (0600) in "+store.Dir())
		fmt.Fprintln(errw, "!!! Anyone who can read your files can read your clipboard history key.")
		fmt.Fprintln(errw, "!!! This is only appropriate for headless machines without an OS keychain.")
		fmt.Fprintln(errw, "")
	}
	fmt.Fprintf(out, "Key storage: %s\n", store.Backend())
}

func readEnrollToken() (string, error) {
	if t := strings.TrimSpace(os.Getenv("ECB_ENROLL_TOKEN")); t != "" {
		return t, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no enrollment token: set ECB_ENROLL_TOKEN (the token is never accepted as a flag)")
	}
	fmt.Fprint(errw, "Relay enrollment token (hidden): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(errw)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("empty enrollment token")
	}
	return t, nil
}

func cmdInit(args []string) error {
	fs := newFlagSet("init", "Create a new sync group on a relay. The relay's enrollment token is read\nfrom ECB_ENROLL_TOKEN or prompted (never a flag).")
	relayURL := fs.String("relay", os.Getenv("ECB_RELAY"), "relay base URL, e.g. https://ecb.example.com")
	name := fs.String("name", "", "name of this device (default: hostname)")
	allowFile := fs.Bool("allow-file-keystore", false, "allow storing the device key in a plaintext 0600 file if the OS keychain is unavailable")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("init takes no arguments")
	}
	if *relayURL == "" {
		return usagef("init needs --relay URL")
	}
	base, err := normaliseRelay(*relayURL)
	if err != nil {
		return err
	}
	devName := strings.TrimSpace(*name)
	if devName == "" {
		devName = hostnameOr("device")
	}
	if len(devName) > roster.MaxNameLen {
		return usagef("--name must be at most %d bytes", roster.MaxNameLen)
	}
	store, err := openStore(*allowFile)
	if err != nil {
		return err
	}
	if st, err := store.LoadState(); err == nil && st.RelayURL != "" {
		return errors.New("this device already belongs to a group (config dir " + store.Dir() + "); remove that directory to start over")
	}
	token, err := readEnrollToken()
	if err != nil {
		return err
	}
	id, created, err := store.LoadOrCreateIdentity()
	if err != nil {
		if errors.Is(err, keystore.ErrKeychainUnavailable) {
			return fmt.Errorf("%w\nNo usable OS keychain. On a headless machine re-run with --allow-file-keystore (stores the key in a 0600 file)", err)
		}
		return err
	}
	if created {
		fmt.Fprintln(out, "Created a new device identity.")
	}
	reportBackend(store)

	gid, err := randomGroupID()
	if err != nil {
		return err
	}
	genesis, err := roster.NewGenesis(gid, roster.NewEntry(devName, id.Recipient(), id.PublicKey(), time.Now().UnixMilli()), id.Ed25519)
	if err != nil {
		return err
	}
	st := &keystore.State{RelayURL: base, GroupID: gid}
	cl, err := client.New(client.Config{BaseURL: base, Identity: id, GroupID: gid, State: st, Store: store,
		Roster: client.RosterFunc(func() (*roster.Roster, error) { return genesis, nil })})
	if err != nil {
		return err
	}
	ctx, cancel := ctxTimeout(60 * time.Second)
	defer cancel()
	if err := cl.CreateGroup(ctx, token, genesis); err != nil {
		if client.IsStatus(err, 403) || client.IsStatus(err, 401) {
			return errors.New("the relay rejected the enrollment token")
		}
		return friendlyNet(err, base)
	}
	blob, err := genesis.Seal()
	if err != nil {
		return err
	}
	st.RosterBlob = blob
	if err := store.SaveState(st); err != nil {
		return err
	}
	fmt.Fprintf(out, "Group created on %s as device %q.\nNext: run `ecb pair` here and `ecb join` on your other device, then `ecb run` everywhere.\n", base, devName)
	return nil
}

func cmdPair(args []string) error {
	fs := newFlagSet("pair", "Add a device: shows a one-time code to type on the new device with `ecb join`.\nThe code is valid for 5 minutes and one attempt.")
	secret := fs.String("code", "", "choose your own secret instead of 3 random words (min 8 chars; visible in the process list, so prefer the default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("pair takes no arguments")
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	l, err := loadLocal(store)
	if err != nil {
		return err
	}
	if *secret != "" {
		if _, err := pairing.NewCode(1, *secret); err != nil {
			return usagef("%v", err)
		}
		if w := pairing.SecretWarning(*secret); w != "" {
			fmt.Fprintln(errw, "WARNING:", w)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cl, err := l.client()
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = l.syncRoster(sctx, cl)
	cancel()
	if err != nil {
		return friendlyNet(err, l.state.RelayURL)
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	mailbox, ttl, err := cl.PairCreate(pctx)
	cancel()
	if err != nil {
		return friendlyNet(err, l.state.RelayURL)
	}
	code, err := pairing.NewCode(mailbox, *secret)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Pairing code: %s\n", code)
	fmt.Fprintf(out, "On the new device run:  ecb join --relay %s %s\n", l.state.RelayURL, code)
	fmt.Fprintf(out, "Valid for %d minutes, one attempt. Waiting (Ctrl-C to cancel)...\n", int(ttl.Minutes()))

	inv := &pairing.Inviter{
		MB: cl.Mailbox(), Self: l.id, Roster: l.ros, RelayURL: l.state.RelayURL, Timeout: ttl,
		Publish: func(ctx context.Context, r *roster.Roster) error {
			if err := cl.PublishRoster(ctx, r); err != nil {
				return err
			}
			return l.saveRoster(r)
		},
	}
	res, err := inv.Run(ctx, code)
	if err != nil {
		if errors.Is(err, pairing.ErrConfirmation) {
			return fmt.Errorf("%w\nNothing was changed. Start again with `ecb pair`", err)
		}
		return err
	}
	fmt.Fprintf(out, "Paired: %q (%s) is now part of the group (%d devices).\n", res.Added.Name, shortID(res.Added.DeviceID), len(res.Roster.Entries))
	return nil
}

func cmdJoin(args []string) error {
	fs := newFlagSet("join", "Join an existing group with the code shown by `ecb pair` on a paired device.\nUsage: ecb join [--relay URL] [--name NAME] <code>")
	relayURL := fs.String("relay", os.Getenv("ECB_RELAY"), "relay base URL (or ECB_RELAY)")
	name := fs.String("name", "", "name of this device (default: hostname)")
	allowFile := fs.Bool("allow-file-keystore", false, "allow storing the device key in a plaintext 0600 file if the OS keychain is unavailable")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("join needs exactly one <code> (like 7-orbit-velvet-candle)")
	}
	code, err := pairing.ParseCode(pos[0])
	if err != nil {
		return usagef("%v", err)
	}
	if *relayURL == "" {
		return usagef("join needs --relay URL (or ECB_RELAY)")
	}
	base, err := normaliseRelay(*relayURL)
	if err != nil {
		return err
	}
	devName := strings.TrimSpace(*name)
	if devName == "" {
		devName = hostnameOr("device")
	}
	store, err := openStore(*allowFile)
	if err != nil {
		return err
	}
	if st, err := store.LoadState(); err == nil && st.RelayURL != "" {
		return errors.New("this device already belongs to a group (config dir " + store.Dir() + "); remove that directory to start over")
	}
	id, _, err := store.LoadOrCreateIdentity()
	if err != nil {
		if errors.Is(err, keystore.ErrKeychainUnavailable) {
			return fmt.Errorf("%w\nNo usable OS keychain. On a headless machine re-run with --allow-file-keystore", err)
		}
		return err
	}
	reportBackend(store)
	mb, err := client.NewMailbox(base, nil)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	jn := &pairing.Joiner{
		MB: mb, Self: id, Name: devName,
		Finish: func(ctx context.Context, j *pairing.Joined) error {
			// The relay admitted our key when the inviter published the roster.
			cl, err := client.New(client.Config{BaseURL: base, Identity: id, GroupID: j.GroupID,
				Roster: client.RosterFunc(func() (*roster.Roster, error) { return j.Roster, nil })})
			if err != nil {
				return err
			}
			if err := cl.Authenticate(ctx); err != nil {
				return fmt.Errorf("the relay does not accept this device: %w", err)
			}
			blob, err := j.Roster.Seal()
			if err != nil {
				return err
			}
			return store.SaveState(&keystore.State{RelayURL: base, GroupID: j.GroupID, RosterBlob: blob})
		},
	}
	fmt.Fprintln(out, "Connecting to the relay and checking the code...")
	j, err := jn.Run(ctx, code)
	if err != nil {
		if errors.Is(err, pairing.ErrConfirmation) {
			return fmt.Errorf("%w\nCheck the code and ask for a new one with `ecb pair`", err)
		}
		return err
	}
	fmt.Fprintf(out, "Joined the group as %q (%d devices). Start syncing with `ecb run`.\n", devName, len(j.Roster.Entries))
	return nil
}

func cmdDevices(args []string) error {
	if len(args) > 0 && args[0] == "rm" {
		return cmdDevicesRm(args[1:])
	}
	fs := newFlagSet("devices", "List the devices in your group. `ecb devices rm <name>` removes one.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("unknown devices subcommand %q (try `ecb devices rm <name>`)", fs.Arg(0))
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	l, err := loadLocal(store)
	if err != nil {
		return err
	}
	if cl, err := l.client(); err == nil {
		ctx, cancel := ctxTimeout(10 * time.Second)
		if err := l.syncRoster(ctx, cl); err != nil {
			fmt.Fprintf(errw, "note: could not refresh from the relay (%v); showing the local roster\n", err)
		}
		cancel()
	}
	fmt.Fprintf(out, "%-24s %-10s %s\n", "NAME", "ID", "ADDED")
	self := l.id.DeviceID()
	for _, e := range l.ros.Entries {
		mark := ""
		if e.DeviceID == self {
			mark = "  (this device)"
		}
		fmt.Fprintf(out, "%-24s %-10s %s%s\n", e.Name, shortID(e.DeviceID), time.UnixMilli(e.AddedAtMs).Format("2006-01-02 15:04"), mark)
	}
	return nil
}

func cmdDevicesRm(args []string) error {
	fs := newFlagSet("devices rm", "Remove a device from the group: publishes a new signed roster; the relay\nstops accepting the device immediately. Usage: ecb devices rm [--force] <name>")
	force := fs.Bool("force", false, "allow removing this device itself")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("devices rm needs exactly one device <name>")
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	l, err := loadLocal(store)
	if err != nil {
		return err
	}
	cl, err := l.client()
	if err != nil {
		return err
	}
	ctx, cancel := ctxTimeout(60 * time.Second)
	defer cancel()
	if err := l.syncRoster(ctx, cl); err != nil {
		return friendlyNet(err, l.state.RelayURL)
	}
	var target *roster.Entry
	for i := range l.ros.Entries {
		if l.ros.Entries[i].Name == pos[0] {
			target = &l.ros.Entries[i]
		}
	}
	if target == nil {
		return fmt.Errorf("no device named %q (see `ecb devices`)", pos[0])
	}
	if target.DeviceID == l.id.DeviceID() && !*force {
		return errors.New("that is this device; removing it locks you out of the group. Use --force if you really mean it")
	}
	next, err := l.ros.Remove(target.DeviceID)
	if err != nil {
		return err
	}
	if err := next.Sign(l.id.Ed25519); err != nil {
		return err
	}
	if err := cl.PublishRoster(ctx, next); err != nil {
		return friendlyNet(err, l.state.RelayURL)
	}
	if target.DeviceID != l.id.DeviceID() {
		if err := l.saveRoster(next); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Removed %q. The relay no longer accepts it and new items are not encrypted to it.\n", pos[0])
	return nil
}

func cmdRun(args []string) error {
	fs := newFlagSet("run", "Run the sync daemon in the foreground (Ctrl-C to stop). Run it as a user\nservice to start it at login; see contrib/.")
	verbose := fs.Bool("verbose", false, "debug logging (never includes clipboard content)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return usagef("run takes no arguments")
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	l, err := loadLocal(store)
	if err != nil {
		return err
	}
	if os.Getenv(clip.EnvBackend) != "" {
		fmt.Fprintln(errw, "NOTE: ECB_CLIPBOARD_BACKEND is set: using the TEST-ONLY file clipboard, not the OS clipboard.")
	}
	cb, err := clip.New()
	if err != nil {
		return err
	}
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(errw, &slog.HandlerOptions{Level: lvl}))
	d, err := daemon.New(daemon.Options{Store: store, Identity: l.id, Clip: cb, Logger: log})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		select {
		case <-d.Ready():
			log.Info("connected to the relay")
		case <-ctx.Done():
		}
	}()
	if err := d.Run(ctx); err != nil {
		if errors.Is(err, daemon.ErrRevoked) {
			return fmt.Errorf("%w\nIf this was a mistake, re-add the device with `ecb pair` on another device and `ecb join` here (after removing %s)", err, store.Dir())
		}
		return err
	}
	return nil
}

func cmdMode(args []string) error {
	fs := newFlagSet("mode", "Set the sync mode (applies to a running daemon within ~2 seconds).\nUsage: ecb mode <both|send-only|receive-only|paused>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		store, err := openStore(false)
		if err == nil {
			if c, err := daemon.LoadConfig(store.Dir()); err == nil {
				fmt.Fprintf(out, "current mode: %s\n", c.Mode)
			}
		}
		return usagef("mode needs one of: both, send-only, receive-only, paused")
	}
	return cmdSetMode("mode", fs.Arg(0), nil)
}

func cmdSetMode(name, mode string, extra []string) error {
	if name != "mode" {
		fs := newFlagSet(name, "Shortcut for `ecb mode "+mode+"`.")
		if err := fs.Parse(extra); err != nil {
			return err
		}
	}
	if !daemon.ValidMode(mode) {
		return usagef("invalid mode %q (want both, send-only, receive-only or paused)", mode)
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	if err := daemon.SetMode(store.Dir(), mode); err != nil {
		return err
	}
	fmt.Fprintf(out, "Mode set to %s. A running `ecb run` picks it up within ~2 seconds.\n", mode)
	return nil
}

func cmdStatus(args []string) error {
	fs := newFlagSet("status", "Show relay reachability, group, devices, mode and key storage. No secrets.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := openStore(false)
	if err != nil {
		return err
	}
	l, err := loadLocal(store)
	if err != nil {
		return err
	}
	cfg, cerr := daemon.LoadConfig(store.Dir())
	fmt.Fprintf(out, "config dir:  %s\n", store.Dir())
	fmt.Fprintf(out, "key storage: %s\n", store.Backend())
	fmt.Fprintf(out, "relay:       %s\n", l.state.RelayURL)
	fmt.Fprintf(out, "group:       %x\n", l.state.GroupID[:4])
	if me, ok := l.ros.Lookup(l.id.DeviceID()); ok {
		fmt.Fprintf(out, "this device: %s (%s)\n", me.Name, shortID(me.DeviceID))
	}
	if cerr != nil {
		fmt.Fprintf(out, "mode:        %s (config unreadable: %v)\n", cfg.Mode, cerr)
	} else {
		fmt.Fprintf(out, "mode:        %s (max text %d B, max image %d B)\n", cfg.Mode, cfg.MaxTextBytes, cfg.MaxImageBytes)
	}
	if cl, err := l.client(); err == nil {
		ctx, cancel := ctxTimeout(10 * time.Second)
		defer cancel()
		switch err := l.syncRoster(ctx, cl); {
		case err == nil:
			fmt.Fprintln(out, "relay state: reachable, this device is authenticated")
		case client.IsStatus(err, 401) || client.IsStatus(err, 403):
			fmt.Fprintln(out, "relay state: reachable, but it REFUSES this device (removed from the group?)")
		default:
			fmt.Fprintf(out, "relay state: unreachable (%v)\n", err)
		}
	}
	fmt.Fprintf(out, "roster:      version %d, %d device(s)\n", l.ros.Version, len(l.ros.Entries))
	for _, e := range l.ros.Entries {
		fmt.Fprintf(out, "  - %s (%s)\n", e.Name, shortID(e.DeviceID))
	}
	return nil
}
