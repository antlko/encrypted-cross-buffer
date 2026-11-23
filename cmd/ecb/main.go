// Command ecb syncs the clipboard between your own devices, end-to-end
// encrypted through an untrusted relay. Run `ecb help` for a walkthrough.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

// usageError is a mistake in how ecb was invoked (exit code 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

type command struct {
	name    string
	summary string
	run     func(args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"init", "create a new sync group on a relay (first device)", cmdInit},
		{"pair", "add another device: show a one-time code (run on a paired device)", cmdPair},
		{"join", "join an existing group with the code from `ecb pair` (new device)", cmdJoin},
		{"devices", "list devices; `devices rm <name>` removes one", cmdDevices},
		{"run", "run the sync daemon in the foreground", cmdRun},
		{"mode", "set sync mode: both | send-only | receive-only | paused", cmdMode},
		{"pause", "stop syncing (same as `mode paused`)", func(a []string) error { return cmdSetMode("pause", ModePausedName, a) }},
		{"resume", "resume syncing (same as `mode both`)", func(a []string) error { return cmdSetMode("resume", "both", a) }},
		{"status", "show relay reachability, group, devices, mode", cmdStatus},
		{"doctor", "check whether the relay is reachable from this network (DNS, TLS, WebSocket...)", cmdDoctor},
		{"version", "print the version", cmdVersion},
	}
}

// ModePausedName avoids importing daemon constants into the table above.
const ModePausedName = "paused"

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	out, errw = stdout, stderr
	if len(args) == 0 {
		fmt.Fprint(stderr, helpText())
		return 2
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "--help", "-help":
		if len(rest) > 0 {
			for _, c := range commands {
				if c.name == rest[0] {
					return exitCode(c.run([]string{"--help"}))
				}
			}
		}
		fmt.Fprint(stdout, helpText())
		return 0
	case "-v", "--version":
		name = "version"
	}
	for _, c := range commands {
		if c.name == name {
			return exitCode(c.run(rest))
		}
	}
	fmt.Fprintf(stderr, "ecb: unknown command %q\n\n%s", name, helpText())
	return 2
}

func exitCode(err error) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(errw, "ecb: %v\nRun `ecb help` for usage.\n", err)
		return 2
	}
	fmt.Fprintf(errw, "ecb: %v\n", err)
	return 1
}

var (
	out  io.Writer = os.Stdout
	errw io.Writer = os.Stderr
)

func helpText() string {
	var b strings.Builder
	b.WriteString(`ecb - encrypted clipboard sync between your own devices

The relay (a small server you host) never sees your clipboard: items are
encrypted and signed on your devices.

Quick start
  1. On your relay host, set ECB_ENROLL_TOKEN (a long random secret) and run ecb-relay.
  2. First device:   ecb init --relay https://ecb.example.com
                     (it asks for the enroll token; or set ECB_ENROLL_TOKEN)
  3. Add a device:   on a device that is already set up run   ecb pair
                     it shows a code like 7-orbit-velvet-candle (valid 5 minutes)
                     on the new device run   ecb join --relay https://ecb.example.com 7-orbit-velvet-candle
  4. On every device run   ecb run   (or install it as a service, see contrib/)
  5. Copy on one device, paste on the others.

Commands
`)
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-9s %s\n", c.name, c.summary)
	}
	b.WriteString(`
Use "ecb <command> --help" for the options of a command.

Environment
  ECB_CONFIG_DIR     config directory (default: your OS user config dir, in "ecb")
  ECB_ENROLL_TOKEN   relay enrollment token for "ecb init" (never pass it as a flag)
  ECB_KEYSTORE       auto | keychain | file   where the device key is kept
  ECB_RELAY          default relay URL for "ecb join"

Items that password managers mark as sensitive are never synced. Text and PNG
images up to 8 MiB each are synced; files are not.
`)
	return b.String()
}

func cmdVersion(args []string) error {
	fs := newFlagSet("version", "Print the ecb version.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintln(out, "ecb", version)
	return nil
}
