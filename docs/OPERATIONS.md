# ecb - operations guide

How to deploy, configure, back up, upgrade and recover the relay (`ecb-relay`), and how to manage devices. For the concepts behind this, see [TECHNICAL.md](TECHNICAL.md); for the security model, [SECURITY.md](SECURITY.md).

Contents: [Deploy](#deploy-step-by-step) - [Configuration](#relay-configuration-reference) - [Backup and restore](#backup-and-restore) - [Upgrades](#upgrades) - [Logging](#what-is-and-is-not-logged) - [Enroll token](#rotating-the-enroll-token) - [Revoking a device](#revoking-a-device) - [Recovery](#recovering-after-losing-all-devices) - [Monitoring](#monitoring) - [Hardening](#hardening) - [Runbook](#troubleshooting-runbook)

## Deploy step by step

Requirements: a host with Docker Engine and the Compose plugin (`docker compose version` works), outbound internet access, and for the recommended setup a Cloudflare account with a domain. The relay needs about 512 MB of memory at most and a little disk (see [Monitoring](#monitoring)).

1. **Get the code.**

   ```bash
   git clone https://github.com/antlko/encrypted-cross-buffer.git
   cd encrypted-cross-buffer
   ```

2. **Create `.env`** (git-ignored; never commit it).

   ```bash
   cp .env.example .env
   chmod 600 .env
   openssl rand -hex 24      # paste the output as ECB_ENROLL_TOKEN
   ```

   `ECB_ENROLL_TOKEN` is required and must be at least 16 characters; Compose refuses to start without it.

3. **Create a Cloudflare Tunnel** (production). *Dashboard labels change over time.*
   1. Zero Trust > Networking > Tunnels > **Create a tunnel** > Cloudflared.
   2. Choose **Docker**, copy only the token from the shown command into `.env` as `TUNNEL_TOKEN`.
   3. In the tunnel: **Routes > Add > Published application**. Hostname, for example `ecb.example.com`; **Service URL** `http://relay:8080`.
   4. Do **not** put Cloudflare Access (a login page) in front of this hostname: the `ecb` client cannot answer a login challenge.

4. **Start.**

   ```bash
   docker compose --profile tunnel up -d --build
   docker compose ps
   docker compose logs relay | tail
   ```

   Expected: `relay` is `healthy`, `cloudflared` is `running`, and the relay log contains `relay listening addr=:8080 max_item_bytes=33554432 item_ttl=10m0s`.

5. **Verify from outside.** `curl https://ecb.example.com/healthz` prints `ok`.

6. **Create the group** on your first device: `ecb init --relay https://ecb.example.com` (see the README). Add more devices with `ecb pair` / `ecb join`.

**Local test without a tunnel:**

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
curl http://127.0.0.1:8080/healthz
```

This publishes the relay on `127.0.0.1:8080` only and sets `ECB_TRUST_PROXY_HEADERS=false` (there is no proxy to trust). `cloudflared` is not started because it belongs to the `tunnel` profile.

**What Compose sets up** (see `docker-compose.yml`): relay image built from the `Dockerfile` (static binary, distroless `nonroot` base), named volume `ecb-data` at `/data`, no published port (the relay is only reachable by `cloudflared` on the private Compose network), read-only root filesystem with a `/tmp` tmpfs, all capabilities dropped, `no-new-privileges`, 512 MB memory limit, 256 pids, health check (`/ecb-relay -healthcheck`), `restart: unless-stopped` and log rotation (10 MB x 3). `cloudflared` is pinned to a specific image tag; bump it deliberately.

## Relay configuration reference

The relay is configured only by environment variables (no config file, no secrets on the command line). The only command-line flag is `-healthcheck`.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `ECB_ENROLL_TOKEN` | **yes** | none | Secret needed to create a new group (`ecb init`). At least 16 characters, otherwise the relay refuses to start. Never logged. |
| `ECB_ADDR` | no | `:8080` | Listen address. The image sets `:8080`. The health check probes `127.0.0.1` on this port. |
| `ECB_DATA_DIR` | no | `/data` | Where `groups.json` and the item spool live. The image sets `/data`; in Compose it is the `ecb-data` volume. Must be writable by uid 65532 in the container. |
| `ECB_MAX_ITEM_BYTES` | no | `33554432` (32 MiB) | Largest accepted upload, measured on the **whole frame** (126 bytes of overhead plus ciphertext). Integer, at least 1024. Larger uploads get HTTP 413. *The stock `ecb` client caps ciphertext at 32 MiB, so values above 32 MiB do not let the client send more; use this to lower the cap.* Keep it well below Cloudflare's request body limit (about 100 MB on lower plans; external, re-verify). |
| `ECB_ITEM_TTL` | no | `10m` | How long the latest item of a group is kept. Go duration (`90s`, `10m`). *Clients reject items older than 10 minutes plus 5 minutes of clock skew, so raising this above 10 minutes does not help the stock client; lowering it shortens how long an offline device can catch up.* |
| `ECB_TRUST_PROXY_HEADERS` | no | `false` in the binary; `true` in `docker-compose.yml`; `false` in `docker-compose.local.yml` | When `true`, rate limits identify clients by the `CF-Connecting-IP` header (a literal IP; `X-Forwarded-For` is never trusted). Set `true` **only** when the relay is reachable exclusively through Cloudflare's tunnel. Behind any other proxy leave it `false`: all clients then share the proxy's address in the rate limiters. Parsed as a Go boolean (`true`, `false`, `1`, `0`, ...). |

Variables read only by Compose: `TUNNEL_TOKEN` (the Cloudflare tunnel token; required for the `tunnel` profile, secret) and the overrides above, which Compose passes through from `.env` (`ECB_MAX_ITEM_BYTES`, `ECB_ITEM_TTL`, `ECB_TRUST_PROXY_HEADERS`).

Not configurable (compiled in): rate limits, session token lifetime (15 min), nonce lifetime (60 s), pairing mailbox lifetime (5 min), 64 devices per group, 25 s WebSocket pings, 64-event notification ring.

Changing configuration: edit `.env`, then `docker compose --profile tunnel up -d` (Compose recreates the relay with the new environment). Connected devices reconnect by themselves.

## Backup and restore

What is stored (see [TECHNICAL.md section 13](TECHNICAL.md#13-data-at-rest)):

- `/data/groups.json` - **the only state worth backing up.** It holds, per group, the group id, the allowed Ed25519 public keys, the sealed roster and its version. It contains **no secrets and no clipboard content**, but it is metadata (who is in your group), so protect the backup anyway.
- `/data/items/` - the latest sealed item per group. Ephemeral; the relay deletes it at every start. Do not back it up.

Back up (works while the relay runs; the file is written atomically):

```bash
docker volume ls | grep ecb-data          # the exact name has your Compose project prefix
docker run --rm -v <project>_ecb-data:/data:ro -v "$PWD":/backup alpine \
  cp /data/groups.json /backup/groups.json.bak
chmod 600 groups.json.bak
```

Restore:

```bash
docker compose --profile tunnel stop relay
docker run --rm -v <project>_ecb-data:/data -v "$PWD":/backup alpine \
  sh -c 'cp /backup/groups.json.bak /data/groups.json && chown 65532:65532 /data/groups.json && chmod 600 /data/groups.json'
docker compose --profile tunnel up -d
```

*Restoring an old backup restores an old device list.* Devices removed after the backup would be admitted again by the relay (they still cannot read new items, because other devices no longer encrypt to them and reject their signatures), and devices added after the backup would be refused (HTTP 401). The next successful `ecb pair` publishes the full, current roster from the device that ran it and repairs this. If a device cannot get back in, remove its config folder and pair it again.

**Without any backup** the situation is the same as a lost `groups.json`: devices are refused by the relay. Recreate by `ecb init` on one device and re-pairing the others (see Recovery below). You lose nothing but the setup effort, because the clipboard history is not kept.

Device-side state (keys, roster copy, counters) lives in each computer's config folder and the OS keychain. There is no way to back up and restore keys through `ecb`; the supported way to replace a device is to pair a new one.

## Upgrades

Relay:

```bash
cd encrypted-cross-buffer
git pull
docker compose --profile tunnel up -d --build
docker compose ps
```

The data volume persists. In-flight items (at most one per group, at most 10 minutes old) are discarded at restart; devices re-authenticate and reconnect automatically (sessions are in memory). Expect a few seconds of interruption.

`cloudflared`: edit the pinned tag in `docker-compose.yml` deliberately (look at Cloudflare's release notes), then `docker compose --profile tunnel up -d`.

Clients: download the new archive from the Releases page (or rebuild from source with `git pull && make build`) and replace the binary; restart `ecb run` (or your service). The frame format is version 1; receivers reject unknown versions, so read the release notes before upgrading across a change that bumps it, and upgrade all devices before relying on a new content type. Mixed versions are fine as long as the wire format has not changed.

## What is and is not logged

The relay writes structured text logs to stderr (`docker compose logs relay`). Docker keeps three files of 10 MB each.

Logged:

- Start-up: `relay listening` with the address, `max_item_bytes` and `item_ttl`; `shutting down`.
- One line per request: a random request id (`rid`, also returned as the `X-Request-Id` header), HTTP method, the **route pattern** (for example `GET /v1/items/{id}`, never the actual id), status, `bytes_in`, `bytes_out`, `dur_ms`.
- Errors without detail: `panic`, `persist groups failed`, `spool create failed`.

Never logged: request or response bodies, headers (so no bearer tokens or enroll token), query strings (the WebSocket `?token=` form is therefore not logged), client IP addresses, group ids, device keys, item ids, anything from the clipboard.

*Other components log on their own:* Cloudflare keeps its own request logs and analytics (including client IPs); `cloudflared` logs its connection state to the container log. The device-side `ecb run` logs to stderr (never content or keys); `--verbose` adds debug detail, still without content.

## Rotating the enroll token

The enroll token only authorises **creating new groups**. Existing groups and devices do not use it, so rotating it does not disconnect anyone.

1. Generate a new value: `openssl rand -hex 24`.
2. Put it in `.env` as `ECB_ENROLL_TOKEN`.
3. `docker compose --profile tunnel up -d` (recreates the relay; devices reconnect).
4. From now on `ecb init` needs the new value. Clear old values from shell history and password notes.

Rotate it if it was exposed, or after you finish adding your first device. There is no need to keep it around: `ecb init` is the only command that uses it. *Anyone holding it can create their own groups on your relay and consume its disk and bandwidth; they cannot read your group.*

## Revoking a device

Use this when a computer is lost, stolen, sold or retired.

1. On any **other** set-up device: `ecb devices` (note the name), then `ecb devices rm <name>`.
2. You should see `Removed "<name>". The relay no longer accepts it and new items are not encrypted to it.`
3. Check with `ecb devices` and `ecb status` on a second device.

Effects: the relay drops the device's key immediately, closes its WebSocket and long-poll connections, and answers its next authentication with 401; the device stops with `this device has been removed from the group`. Other devices pick up the new roster on their next event, within 5 minutes at most, or when they next send, and stop encrypting to the removed device.

Limits (be honest with yourself): it cannot take back what the device already received or what is still on its clipboard; items captured earlier remain readable with its keys (no forward secrecy); a removal needs a working device, so if the **only** other device is the one you want to remove, see Recovery. `ecb devices rm` refuses to remove the device you run it on unless you add `--force`, because that locks you out of the group.

If the removed device is yours and you will reuse it: delete its config folder (path shown by `ecb status`) and the keychain entry named `ecb`, then pair it again.

## Recovering after losing all devices

Nobody holds your keys: not the relay, not Cloudflare. **If every device of a group is lost, the group cannot be recovered.** Start a new one:

1. (Optional but tidy) on the relay host, remove the old group data. This also removes every other group on this relay: `docker compose --profile tunnel stop relay`, delete `groups.json` from the volume (for example `docker run --rm -v <project>_ecb-data:/data alpine rm -f /data/groups.json`), then `docker compose --profile tunnel up -d`. Skip this if other groups share the relay; the old group is harmless and inert.
2. On the first new device: `ecb init --relay https://ecb.example.com` (you need the enroll token from `.env`; rotate it first if you think it leaked).
3. Add the others with `ecb pair` / `ecb join`.

If you still have **one** device, nothing is lost: pair new devices from it and remove the lost ones with `ecb devices rm`.

## Monitoring

- **Liveness:** `GET /healthz` returns `200 ok` with no authentication. Point an external uptime monitor at `https://<your host>/healthz`. Inside the container the health check is `/ecb-relay -healthcheck` (probes `127.0.0.1:<port of ECB_ADDR>`); `docker compose ps` shows `healthy` or `unhealthy`.
- **Logs:** `docker compose logs -f relay`. Watch for a rising share of status 401 (devices removed or broken), 429 (rate limiting or abuse), 413 (oversized items) and 5xx (disk or bug).
- **Disk:** bounded by (item cap) x (number of groups) plus in-flight uploads, so a personal relay needs only tens of MB. `docker system df -v` shows the volume size.
- **Memory:** the relay streams items; memory does not grow with item size. The container is capped at 512 MB.
- **Tunnel:** `docker compose logs cloudflared` shows connection state; the Cloudflare dashboard shows the tunnel as healthy or down.
- There is **no metrics endpoint** in this version.

## Hardening

- **Never publish the relay port.** The default Compose file uses `expose` only, so the port exists on the private Compose network and `cloudflared` is the only way in. Do not add `ports:` for `8080` in production. The relay speaks plain HTTP; TLS is terminated by Cloudflare (or your own proxy).
- **`ECB_TRUST_PROXY_HEADERS`.** `true` is correct only when the *only* path to the relay is a proxy that sets `CF-Connecting-IP` honestly (the tunnel). If you can reach the relay port directly, an attacker can forge that header and evade per-IP rate limits, and every request would appear to come from forged addresses. For direct or local use set it to `false`.
- **Keep the enroll token secret** and rotate it as described above. It cannot read data, but it creates groups.
- **Host:** keep Docker and the OS updated; restrict SSH; the `.env` file contains the enroll and tunnel tokens (`chmod 600 .env`). Anyone with the `TUNNEL_TOKEN` can run a tunnel connector for your hostname; revoke or roll the tunnel in the dashboard if it leaks.
- **Cloudflare:** consider a WAF or rate-limiting rule for the hostname; keep "Always use HTTPS" on. Do not add an Access login in front (clients cannot pass it).
- **Container:** the Compose file already drops all capabilities, enforces a read-only filesystem and non-root user, and sets memory and pid limits. Do not weaken them.
- **Clients:** prefer the OS keychain; avoid `--allow-file-keystore` except on headless machines; always use `https://` relay URLs (`ecb init` and `ecb join` refuse plain `http://` to a non-local host unless `--insecure` is given).

## Troubleshooting runbook

| Symptom | How to diagnose | Fix |
| --- | --- | --- |
| `docker compose up`: `set ECB_ENROLL_TOKEN in .env` | `.env` missing or empty value | Create `.env` from `.env.example`, set the token, retry. |
| Relay exits at start: `ECB_ENROLL_TOKEN is required and must be at least 16 characters` | `docker compose logs relay` | Use `openssl rand -hex 24`. |
| Relay exits: `groups.json: ...` | Corrupt or hand-edited state file | Restore from backup (see above), or delete it and re-create groups. |
| Relay exits: permission denied on `/data` | Volume owned by another uid | Fix ownership to 65532: `docker run --rm -v <project>_ecb-data:/data alpine chown -R 65532:65532 /data`. |
| `relay` is `unhealthy` | `docker compose logs relay` (the image is distroless, there is no shell to exec into) | Check the logs for the startup error; make sure `ECB_ADDR` matches the published/probed port. |
| `cloudflared` restarts or logs auth errors | `docker compose logs cloudflared` | Wrong or empty `TUNNEL_TOKEN`; copy only the token. |
| Cloudflare error 1033 / 502 on the hostname | Dashboard tunnel status; route config | Tunnel not connected, or Service URL is not `http://relay:8080`. |
| `https://host/healthz` works but `ecb` cannot connect | `ecb doctor --relay https://host` | Follow the failing check (DNS, TLS inspection, WebSocket). |
| Devices get 401 repeatedly | `ecb status` says relay REFUSES this device | The device was removed, or the relay lost/restored `groups.json`. See Backup and Revoking. |
| HTTP 413 on send | Log line `item too large`; client warning about size | Item exceeds `ECB_MAX_ITEM_BYTES` or the client limits. Shrink it; do not raise caps beyond what Cloudflare allows. |
| HTTP 429 | Log status 429 | A rate limit was hit (often a retry loop or a shared IP when `ECB_TRUST_PROXY_HEADERS` is `false` behind a proxy). Fix the loop; set the flag correctly. |
| Items arrive late or are missing | `ecb run --verbose` on both ends | Latest-only and 10-minute TTL: a newer item replaced it, or the device was offline longer than the TTL. |
| `envelope: item too old` / `in the future` in verbose logs | Clock difference of more than 5 minutes | Fix time synchronisation (NTP) on the device or the relay host. |
| Pairing fails: `key confirmation failed` | Typo in code, or tampering | Run `ecb pair` again and type the code exactly; the code is one-time. |
| Pairing: `too many active mailboxes` | 4 mailboxes already open for the group | Wait up to 5 minutes for them to expire. |
| WebSocket drops every minute or two | `ecb doctor` | Network idles out connections. The client pings every 25 s and falls back to long-poll after 3 failures; check for a proxy that kills idle connections. |
| Relay disk fills | `docker system df -v` | Unexpected; check for many groups, and for stuck `tmp-*` files under `items/`. Restarting the relay clears the spool. |
| Need a clean slate on a device | - | Stop `ecb run`, remove the config folder (`ecb status` prints it) and the `ecb` keychain entry, then `ecb join` again. |

## Releases and the container image

Pushing a tag such as `v1.0.1` starts `.github/workflows/release.yml`. It runs the tests, builds `ecb` archives
(linux amd64/arm64, macOS amd64/arm64, windows amd64) and `ecb-relay` archives (linux amd64/arm64), publishes a
multi-arch image to `ghcr.io/antlko/encrypted-cross-buffer` (tags `1.0.1`, `1.0`, `1`, `latest`) and creates a
GitHub Release with `SHA256SUMS`. Running the workflow by hand, or pushing changes to `release.yml`, the `Dockerfile`
or `go.mod` to `main`, does a dry run that builds everything and publishes nothing.

For Portainer (or any host without the source) use `docker-compose.portainer.yml`: relay only, published image, no tunnel included (bring your own proxy), port `ECB_PORT` (default 8080) published, `ECB_TRUST_PROXY_HEADERS` default `false`. To run the published image from the regular file instead, replace `build: .` in the `relay` service of `docker-compose.yml`
with `image: ghcr.io/antlko/encrypted-cross-buffer:1.0.0` (pin an exact version).
