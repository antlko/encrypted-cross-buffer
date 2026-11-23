# ecb - encrypted clipboard sync

**Copy on one of your computers, paste on another. Nobody in the middle can read it.**

![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)
![E2EE](https://img.shields.io/badge/E2EE-age%20%2B%20Ed25519-blueviolet)

`ecb` (encrypted cross buffer) keeps the clipboards of your own computers in sync. It has two programs:

- **`ecb`** runs on each of your computers (macOS, Linux, Windows). It watches the clipboard and applies what the other computers copied.
- **`ecb-relay`** is a tiny server that you host yourself. It only passes sealed boxes around.

## Table of contents

- [What it does](#what-it-does)
- [Why another clipboard tool](#why-another-clipboard-tool)
- [How it works in one picture](#how-it-works-in-one-picture)
- [Quick start](#quick-start)
- [Everyday use](#everyday-use)
- [Modes, and advice for a work laptop](#modes-and-advice-for-a-work-laptop)
- [Images](#images)
- [Limits](#limits)
- [Behind a corporate VPN?](#behind-a-corporate-vpn)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Honest limits](#honest-limits)
- [Project layout](#project-layout)
- [Development](#development)
- [Documentation](#documentation)
- [Licence](#licence)

## What it does

- You copy text on computer A. A moment later you can paste it on computer B and C.
- It syncs **text** (including very long text, 10,000+ lines) and **small PNG images** such as screenshots.
- Everything is **encrypted on your computer before it leaves it**. The server, the network and Cloudflare only see sealed bytes.
- Every item is also **signed** by the sending device, so a fake item from the server or from an outsider is rejected.
- Adding a new computer takes one short code (three words) that you type once.
- It does not sync files, folders or clipboard history. *It also does not run on phones yet.*

## Why another clipboard tool

Most clipboard sync tools either send your clipboard through a company's cloud in readable form, or need both computers to see each other on the same network. `ecb` was built for a less friendly situation:

| Need | How ecb handles it |
| --- | --- |
| Your clipboard often contains passwords, tokens and private text | **End-to-end encrypted** (age + Ed25519). The relay cannot decrypt. |
| One computer is on a corporate VPN with no way to reach it from outside | Every device only makes **outbound HTTPS (port 443)** connections. No inbound ports, no LAN needed. |
| You do not want to trust a vendor | You run the relay yourself. The relay is **untrusted by design**: it needs no secret that could read your data. |
| You want it simple to set up | One `docker compose up`, one `ecb init`, one three-word code per extra device. |

## How it works in one picture

```
 computer A                  your relay (Docker)                computer B
 ----------                  -------------------                ----------
 copy text
 compress, encrypt, sign --> stores the sealed box  --notify--> sees "new item"
                             (latest one, 10 min)   <--fetch--- downloads it
                                                                checks signature,
                                                                decrypts, sets clipboard
```

The relay sits behind a Cloudflare Tunnel, so you do not open any port on your router or server. Deep dive with diagrams: [docs/TECHNICAL.md](docs/TECHNICAL.md).

## Quick start

You need: a computer or server that can run Docker (for the relay), and a free Cloudflare account with a domain if you want to reach the relay from anywhere. Total time: about 15 minutes.

### 1. Deploy the server (pick one)

#### Option A: Docker Compose + Cloudflare Tunnel (recommended, reachable from anywhere)

1. Get the code on the server and go into it.

   ```bash
   git clone https://github.com/anatolkzh/encrypted-cross-buffer.git
   cd encrypted-cross-buffer
   ```

2. Create your settings file from the template.

   ```bash
   cp .env.example .env
   openssl rand -hex 24
   ```

   You should see a 48-character random string. Copy it. Open `.env` in an editor and paste it after `ECB_ENROLL_TOKEN=`. This is the **enrollment token**: whoever knows it can create a new sync group on your relay, so keep it private. It is only needed once, when you run `ecb init`. *`.env` is git-ignored; never commit it.*

3. Create the tunnel in the Cloudflare dashboard. *Menu names change from time to time; the idea stays the same.*

   1. Open the Cloudflare dashboard, go to **Zero Trust > Networking > Tunnels**.
   2. Click **Create a tunnel**, choose **Cloudflared**, give it a name such as `ecb`.
   3. Choose the **Docker** environment. The page shows a command containing a long token (it starts with `eyJ`). Copy **only the token**, not the whole command.
   4. Paste the token into `.env` after `TUNNEL_TOKEN=`.
   5. In the tunnel, open **Routes > Add > Published application**. Pick a hostname such as `ecb.example.com` (a domain you own in Cloudflare).
   6. Set **Service URL** to `http://relay:8080`. (`relay` is the name of the Docker service; it is not reachable from the internet except through the tunnel.)

4. Start everything.

   ```bash
   docker compose --profile tunnel up -d --build
   docker compose ps
   ```

   You should see two services, `relay` (status `healthy` after a few seconds) and `cloudflared` (status `running`). The first build takes a minute or two.

5. Check it from outside.

   ```bash
   curl https://ecb.example.com/healthz
   ```

   You should see `ok`. If you do not, see [Troubleshooting](#troubleshooting).

#### Option B: local test without a tunnel (same computer or home network)

This publishes the relay on `127.0.0.1:8080` only. It is good for trying `ecb` out on one machine. *It is plain HTTP and not reachable from other computers.*

```bash
git clone https://github.com/anatolkzh/encrypted-cross-buffer.git
cd encrypted-cross-buffer
cp .env.example .env            # set ECB_ENROLL_TOKEN (use: openssl rand -hex 24)
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
curl http://127.0.0.1:8080/healthz
```

You should see `ok`. Use `http://127.0.0.1:8080` as the relay URL below. No `TUNNEL_TOKEN` is needed (the `cloudflared` service is not started).

### 2. Install `ecb` on each computer

There are no pre-built release binaries yet, so you build it yourself. You need **Go 1.26 or newer** (see https://go.dev/dl/). No C compiler is needed.

**Pick one:**

- **Build from source (macOS and Linux):**

  ```bash
  git clone https://github.com/anatolkzh/encrypted-cross-buffer.git
  cd encrypted-cross-buffer
  make build
  sudo install -m 0755 bin/ecb /usr/local/bin/ecb
  ecb version
  ```

  You should see `ecb dev`.

- **Build from source (Windows, PowerShell, no `make`):**

  ```powershell
  git clone https://github.com/anatolkzh/encrypted-cross-buffer.git
  cd encrypted-cross-buffer
  go build -trimpath -ldflags "-s -w" -o ecb.exe ./cmd/ecb
  .\ecb.exe version
  ```

  Put `ecb.exe` in a folder that is on your `PATH` (for example `C:\Tools`).

- **`go install`** (works once the repository is public and reachable by the Go proxy):

  ```bash
  go install github.com/anatolkzh/encrypted-cross-buffer/cmd/ecb@latest
  ```

  The binary lands in `$(go env GOPATH)/bin`; make sure that folder is on your `PATH`.

Platform notes:

| Platform | Where the secret key is stored | Notes |
| --- | --- | --- |
| macOS | Keychain | The first run may ask to allow access to the keychain. |
| Windows | Credential Manager | Run `ecb` in your normal user session, not as a service. |
| Linux desktop | Secret Service (GNOME Keyring, KWallet) | Needs a running desktop session (X11, or Wayland with data-control). |
| Linux without a keyring | A 0600 file in `~/.config/ecb` | Opt in with `--allow-file-keystore`. *Weaker; see [Honest limits](#honest-limits).* |

### 3. Create your sync group on the first device

On your first computer:

```bash
ecb init --relay https://ecb.example.com
```

It asks `Relay enrollment token (hidden):`. Paste the token from your `.env` and press Enter (nothing is shown while you type). You can also set the `ECB_ENROLL_TOKEN` environment variable instead of typing it.

You should see something like:

```
Created a new device identity.
Key storage: keychain
Group created on https://ecb.example.com as device "my-laptop".
Next: run `ecb pair` here and `ecb join` on your other device, then `ecb run` everywhere.
```

Use `--name` to choose the device name (default: your hostname). On a machine without a keyring add `--allow-file-keystore`. *`ecb init` refuses to run on a computer that already belongs to a group.*

### 4. Add more devices

On a computer that is **already set up**, run:

```bash
ecb pair
```

You should see:

```
Pairing code: 7-orbit-velvet-candle
On the new device run:  ecb join --relay https://ecb.example.com 7-orbit-velvet-candle
Valid for 5 minutes, one attempt. Waiting (Ctrl-C to cancel)...
```

On the **new** computer, type the command it printed (your own code will differ):

```bash
ecb join --relay https://ecb.example.com 7-orbit-velvet-candle
```

You should see `Joined the group as "..." (2 devices). Start syncing with `ecb run`.` and, on the first computer, `Paired: "..." is now part of the group (2 devices).`

Notes:

- The code works **once** and for **5 minutes**. If it fails, run `ecb pair` again for a fresh one.
- You can set the relay once with the `ECB_RELAY` environment variable instead of `--relay`.
- Check the result any time with `ecb devices`.

### 5. Run it, and start it at login

Try it by hand first, on every device:

```bash
ecb run
```

You should see log lines such as `connected to the relay` and `daemon started mode=both devices=2`. Copy some text on one computer and paste it on the other. Stop with Ctrl-C.

To start it automatically at login, use the examples in [`contrib/`](contrib/) (read and edit them first, they are examples):

| Platform | File | What to do |
| --- | --- | --- |
| macOS | [`contrib/com.example.ecb.plist`](contrib/com.example.ecb.plist) | Copy to `~/Library/LaunchAgents/`, fix the path to `ecb`, `launchctl bootstrap gui/$(id -u) ...` |
| Linux | [`contrib/ecb.service`](contrib/ecb.service) | systemd **user** unit: copy to `~/.config/systemd/user/`, `systemctl --user enable --now ecb.service` |
| Windows | [`contrib/windows-task-scheduler.md`](contrib/windows-task-scheduler.md) | A Task Scheduler task that runs at logon. *Do not use a Windows service: it cannot see your clipboard.* |

## Everyday use

| Command | What it does |
| --- | --- |
| `ecb init --relay URL` | Create a new group on a relay (first device only). Plain `http://` is accepted only for localhost unless you add `--insecure`. |
| `ecb pair` | Show a one-time code to add a device (run on a set-up device). |
| `ecb join --relay URL CODE` | Join a group with a code (run on the new device). |
| `ecb run [--verbose]` | Run the sync loop in the foreground. `--verbose` adds debug logs, never clipboard content. |
| `ecb status` | Show the relay, whether it accepts this device, the mode, key storage and the device list. |
| `ecb devices` | List devices. |
| `ecb devices rm NAME` | Remove a device (for example a lost laptop). The relay stops accepting it at once. |
| `ecb mode both\|send-only\|receive-only\|paused` | Change the mode. A running `ecb run` picks it up within about 2 seconds. |
| `ecb pause` / `ecb resume` | Shortcuts for `mode paused` and `mode both`. |
| `ecb doctor` | Test the connection to the relay layer by layer (see [Behind a corporate VPN?](#behind-a-corporate-vpn)). |
| `ecb version` | Print the version. |

Environment variables for `ecb`: `ECB_CONFIG_DIR` (config folder), `ECB_ENROLL_TOKEN` (only for `ecb init`; never a flag), `ECB_KEYSTORE` (`auto`, `keychain` or `file`), `ECB_RELAY` (default relay URL).

## Modes, and advice for a work laptop

| Mode | Sends your copies | Applies other devices' copies |
| --- | --- | --- |
| `both` (default) | yes | yes |
| `send-only` | yes | no |
| `receive-only` | no | yes |
| `paused` | no | no |

**Think before you put this on a company laptop.** Some companies forbid moving data between work and personal devices, and some use data-loss-prevention tools that watch the clipboard. *Check your company's policy first; this tool is not designed to bypass any control.*

If you do use it on a work computer, pick the direction that matches your risk:

- **`receive-only`** on the work laptop if you only want to bring things *in* (for example a link or a snippet from your personal machine). Nothing you copy at work ever leaves the laptop.
- **`send-only`** on the work laptop if you only want to push things *out* to your other devices. Nothing from outside lands in your work clipboard.
- Use `ecb pause` when you handle something sensitive, and `ecb resume` afterwards.

**Password managers are skipped.** If the copying app marks the item as sensitive (most password managers do), `ecb` never syncs it. *This depends on the app setting that flag; it is not a guarantee for every app.*

## Images

- **PNG only**, up to **8 MiB** per image: screenshots and small pictures are the target. Images are sent exactly as the operating system provides them (PNG bytes), without re-encoding.
- A larger image is skipped and a warning is logged (`clipboard image is larger than max_image_bytes; not sent`).
- **No files or folders yet.** Copying a file in your file manager syncs nothing. Large file transfer is a possible future feature (see [docs/TECHNICAL.md](docs/TECHNICAL.md#12-why-p2p-was-deferred-and-the-future-file-transfer-sketch)).
- Limits can be changed per device in `config.json` in the config folder (`max_text_bytes`, `max_image_bytes`). Use the same values on all devices: a device ignores received items larger than its own limit.

## Limits

| What | Value | Where it comes from |
| --- | --- | --- |
| Text per item (default) | 8 MiB | `max_text_bytes` in `config.json` on each device |
| Image per item (default) | 8 MiB, PNG only | `max_image_bytes` in `config.json` |
| Encrypted item size (hard cap) | 32 MiB | relay `ECB_MAX_ITEM_BYTES` (default 33554432) |
| How long the relay keeps an item | 10 minutes | relay `ECB_ITEM_TTL` |
| Items kept per group | **only the latest one** | no history; a newer item replaces the older one |
| Devices per group | 64 | built-in |
| Pairing code lifetime | 5 minutes, one attempt | built-in |
| Decompressed size guard | 256 MiB | built-in, protects against zip bombs |
| File transfer | none | not implemented |

*Because only the latest item is kept for 10 minutes, a device that is offline for longer than that misses it. This is a clipboard, not a backup.*

## Behind a corporate VPN?

Corporate VPNs and proxies sometimes break things that `ecb` needs: long-lived WebSocket connections, or direct access to your domain. Run the built-in diagnostic **before** you blame the app:

```bash
ecb doctor
```

`ecb doctor [--relay URL] [--duration 60s] [--no-ws] [--json]` checks the connection layer by layer and tells you which layer fails. It sends no clipboard items and prints no secrets.

| Check | What it tells you |
| --- | --- |
| URL | The relay URL is well formed. |
| DNS | Your relay hostname resolves from this network (if it does not, doctor also asks a public resolver to compare). |
| TCP | The relay's port (443 for https) is reachable. |
| TLS | The TLS handshake works, and who issued the certificate. *If the issuer is not a well-known public CA, your company may be inspecting HTTPS; doctor says so.* |
| HTTP | `/healthz` answers. |
| Login | This device can authenticate to the relay. |
| WebSocket | A WebSocket stays open for `--duration` (default 60 s) with pings. Skip with `--no-ws`. |
| Long-poll | The slower fallback transport also works. |

Login, WebSocket and long-poll need a set-up device and the relay it is set up with (the URL you test must match the saved relay); otherwise they are skipped and doctor says so. Doctor never sends fake items, so very large uploads are reported as "not tested". `--relay` defaults to `$ECB_RELAY`, then the saved relay.

The result is one of:

- **PASS** - everything works, including WebSocket.
- **PASS-WITH-FALLBACK** - the WebSocket is cut by the network, but long-poll works. `ecb` switches to long-poll by itself after 3 failed WebSocket attempts, so sync still works; it may be slightly slower and uses more small requests.
- **FAIL** - a required step failed, or both WebSocket and long-poll are blocked. Each failing step prints a "what to do" hint you can pass to your IT team (for example "allow outbound HTTPS to `ecb.example.com`"). The command exits with an error code.

`--json` prints the same report in machine-readable form. `--relay` tests another URL; without a matching set-up device only the network layers (URL to HTTP) are tested, which is useful before `ecb init`.

Good to know:

- `ecb` uses only **outbound HTTPS on port 443**. If a browser can reach `https://ecb.example.com/healthz` from that network, `ecb` usually can too. The client honours the standard `HTTPS_PROXY`/`NO_PROXY` environment variables.
- Content stays encrypted even if a company proxy inspects TLS: the proxy would see only sealed items. It would see *metadata* (that you talk to this host, and when).
- If everything fails, try a different hostname for the tunnel, or ask IT to allow it. *Do not work around company network controls.*

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `docker compose up` says `set ECB_ENROLL_TOKEN in .env` | `.env` is missing or the token is empty. Copy `.env.example` to `.env` and set it. |
| `cloudflared` keeps restarting | Wrong or empty `TUNNEL_TOKEN`. Copy only the token from the tunnel's Docker command. |
| `https://.../healthz` gives a Cloudflare error (502/1033) | The route points to the wrong service. Service URL must be `http://relay:8080`, and `relay` must be `healthy` (`docker compose ps`). |
| `ecb init`: `the relay rejected the enrollment token` | The token differs from the relay's `ECB_ENROLL_TOKEN`. After editing `.env`, run `docker compose up -d` again. |
| `ecb init`: `no enrollment token: set ECB_ENROLL_TOKEN` | Not running in a terminal. Export `ECB_ENROLL_TOKEN` first. |
| `ecb init`: `this device already belongs to a group` | Already set up. To start over, remove the config folder it names (this deletes the local identity). |
| `refusing plain http to ...` | You gave an `http://` relay URL for a non-local host. Use `https://`. `--insecure` overrides it, but then the enrollment token and logins cross the network unencrypted. |
| `ecb mode` / `ecb status` mention an invalid `config.json` | The file was edited badly. `ecb run` refuses to start rather than guess. Fix the JSON, or run `ecb mode <mode>`, which keeps the old file as `config.json.bad` and writes a fresh one. |
| `cannot reach the relay at ...` | Wrong URL, DNS, VPN or proxy. Run `ecb doctor --relay URL`. |
| `OS keychain unavailable` | Locked or missing keyring. Unlock it, or on a headless Linux machine add `--allow-file-keystore`. |
| `pairing: key confirmation failed` | Wrong code (typo) or a tampering relay. Nothing was changed; run `ecb pair` again and retype the code carefully. |
| `pairing: timed out waiting for the other device` | The 5 minutes passed, or the other command was not run. Start again with `ecb pair`. |
| `a device named "..." already exists` | Use `ecb join --name OTHER ...`. |
| `ecb run`: `clipboard unavailable` | No desktop session (for example over plain SSH). Run `ecb` inside your graphical login. |
| Nothing arrives on the other device | Check `ecb status` on both (mode, relay state), that `ecb run` is running on both, and that you did not copy something larger than the limits. Try `ecb run --verbose`. |
| `item rejected or unavailable` in the log | The item was replaced by a newer one or expired (10 minutes) before it was fetched. Copy again. |
| `this device has been removed from the group` | Another device ran `ecb devices rm` for it. Delete the config folder and re-join with `ecb pair` / `ecb join`. |
| Windows: copies do not sync | `ecb` must run in your user session (Task Scheduler at logon), not as a service. |

More operational detail: [docs/OPERATIONS.md](docs/OPERATIONS.md).

## FAQ

**Can the server operator (me, or someone who hacks the server) read my clipboard?**
No. Items are encrypted on the sending device to the keys of your other devices. The server holds sealed bytes only.

**Can Cloudflare read it?**
Cloudflare terminates TLS, so it can see the encrypted traffic and metadata (IP addresses, timing, sizes), but not the content, because the content is encrypted inside the TLS.

**Do I need a domain?**
For the Cloudflare Tunnel setup, yes (a domain managed in Cloudflare). For testing on one machine, no (Option B).

**Can I use a different tunnel or a reverse proxy instead of Cloudflare?**
Yes, `ecb-relay` is an ordinary HTTP server on port 8080 that supports WebSocket upgrades. Put any TLS-terminating proxy in front. Set `ECB_TRUST_PROXY_HEADERS` correctly (see [docs/OPERATIONS.md](docs/OPERATIONS.md); it only understands Cloudflare's `CF-Connecting-IP` header, so with another proxy leave it `false`). *Never expose the plain-HTTP port directly to the internet.*

**What happens if the relay is down?**
Nothing is lost on your devices. Syncing pauses; `ecb run` retries with growing delays and resumes by itself.

**Does it work between two computers on the same table?**
Yes, but traffic still goes through the relay. Direct device-to-device transfer is not implemented.

**Does it sync the primary selection (middle-click paste) on Linux?**
No, only the regular clipboard.

**How do I remove a lost laptop?**
On another device run `ecb devices rm <name>`. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for what that does and does not protect.

**I lost all my devices.**
Your group cannot be recovered (by design nobody, including the relay, holds the keys). Create a new one. See [docs/OPERATIONS.md](docs/OPERATIONS.md#recovering-after-losing-all-devices).

**Is there a mobile app?**
No. iOS and Android restrict background clipboard access; a foreground share/paste flow is a possible future step.

## Honest limits

Read these before you trust it with something important. The full list is in [docs/SECURITY.md](docs/SECURITY.md).

- **No forward secrecy.** Items are encrypted to each device's long-lived key. *If a device key is stolen later, anything an attacker recorded earlier (for example from network logs) could be decrypted.* Key rotation is not implemented.
- **The relay sees metadata.** It knows your group's public keys, how many devices you have, which device sent an item and when, how big it was, and IP addresses (Cloudflare also sees the IPs). It does not see content, content type or the pairing code.
- **A compromised device is game over for that group.** A member device can read every new item and can add or remove devices. Remove it with `ecb devices rm` from a clean device, and treat anything copied while it was compromised as exposed.
- **The relay can delay or drop items** (it cannot forge or read them). It can also tell devices apart by timing.
- **Not designed for secrets you cannot afford to lose.** Anything on the clipboard is also available to every program on your computer. The password-manager "sensitive" flag is honoured only when the copying app sets it.
- **No mobile app** and **no file transfer** yet.
- **File-based key storage** (`--allow-file-keystore`) keeps the key in a 0600 file; anyone who can read your files can read your clipboard traffic.
- Not independently audited. It relies on well-known libraries (age, Go's crypto), but the glue code is new.

## Project layout

```
cmd/ecb/            the CLI and sync daemon
cmd/ecb-relay/      the relay server
internal/frame/     outer binary frame and signature
internal/envelope/  compression + age encryption + sign/verify
internal/roster/    signed list of devices
internal/keystore/  device keys (OS keychain or 0600 file) and local state
internal/pairing/   one-time-code pairing (PAKE)
internal/relay/     server: auth, spool, notifications, pairing mailbox
internal/client/    relay client: auth, items, WebSocket and long-poll
internal/daemon/    sync loop, modes, loop prevention
internal/clip/      OS clipboard access
test/integration/   in-process relay + clients
test/e2e/           shell end-to-end test with real binaries
contrib/            autostart examples
docs/               architecture, technical, operations, security, decisions (ADRs)
```

## Development

Requires Go 1.26. No cgo.

| Command | Purpose |
| --- | --- |
| `make build` | Build `bin/ecb` and `bin/ecb-relay`. |
| `make test` | `go test ./... -count=1`. |
| `make race` | Tests with the race detector (what CI runs). |
| `make vet` | `go vet ./...`. |
| `make fmt` | Fails if any file needs `gofmt`. |
| `make e2e` | End-to-end test with fake clipboards in a temp folder; never touches your real clipboard, keychain or config. |
| `make docker-build` | Build the relay image as `ecb-relay:local`. |

CI (`.github/workflows/ci.yml`) runs gofmt, vet, tests with `-race`, cross-builds of `ecb` (linux amd64/arm64, macOS arm64, windows amd64), a Docker build and `govulncheck`.

## Documentation

- [docs/TECHNICAL.md](docs/TECHNICAL.md) - the deep dive: diagrams, byte formats, crypto choices, performance, threat model.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - short as-built overview.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) - deploy, configure, back up, upgrade, revoke, recover.
- [docs/SECURITY.md](docs/SECURITY.md) - security model and what is not protected.
- [docs/decisions/](docs/decisions/) - architecture decision records (ADR-001 to ADR-011).

## Licence

[MIT](LICENSE). Third-party notices: [NOTICE](NOTICE).
