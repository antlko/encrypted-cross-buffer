# Architecture — encrypted-cross-buffer (ecb)

Status: **proposed MVP design** (2026-11-23). Nothing implemented yet. Decisions → `docs/decisions/`,
evidence → `docs/research/`. Facts marked ⏳ are external limits/versions to re-verify.

## 1. What it is
E2EE clipboard sync between **one user's own devices** (macOS / Linux / Windows desktops first).
Copy on device A → appears in the clipboard of devices B, C… Text (incl. 10k+ lines) and PNG images.

## 2. Threat model
- **Untrusted:** the relay server, Cloudflare (terminates TLS → sees everything on the wire), the
  network, the corporate VPN. They must learn **no content, no content type, no pairing code, no keys**.
- **They may learn (accepted metadata):** group id, device count and public keys, IPs, timing, item sizes,
  which device sent an item.
- **Trusted:** member devices. A compromised member device can read items and add/remove devices (MVP
  accepts this; recovery = re-init the group).
- **No forward secrecy** in MVP: items are encrypted to long-lived device X25519 keys; if a device key leaks,
  previously captured ciphertexts (e.g. Cloudflare-side logs) become readable. Mitigation later: key rotation.

## 3. Components
```
 ┌──────── device A (ecb daemon) ───────┐                    ┌──── device B ────┐
 │ clipboard watch → zstd → age(N recip)│  HTTPS 443 only     │ verify → decrypt │
 │ → frame+Ed25519 sig ─── PUT blob ────┼──► Cloudflare ──►  │ → apply clipboard│
 │                    ◄── WS notify ────┼─── Tunnel ──► ecb-relay ◄── GET blob ─┤
 └──────────────────────────────────────┘    (own server: disk spool, auth,     │
                                               roster blob, pairing mailbox)    │
```
- `cmd/ecb` — desktop daemon + CLI (`init`, `pair`, `join`, `devices`, `pause`, `status`).
- `cmd/ecb-relay` — the relay behind Cloudflare Tunnel. Dumb store-and-notify; never decrypts.

## 4. Transport (ADR-001, 002, 003)
- **Relay-only in MVP.** Every device makes outbound HTTPS 443 connections only. This works on the
  NordLayer laptop (no inbound/LAN, Tailscale failed) as long as outbound 443 to the Tunnel host works → **M0 smoke test**.
- **Control channel:** WebSocket `/v1/ws` — tiny JSON notifications only (`{"t":"item","id","size","from"}`),
  client ping every 25 s (⏳ Cloudflare idle ≈100 s), jittered exponential reconnect.
  Behind a Go interface; fallback = long-poll `GET /v1/events?after=<seq>` if a proxy breaks WS.
- **Data channel:** `PUT /v1/items/{id}` / `GET /v1/items/{id}` — one binary blob per item.
  Relay streams the body to a temp file (`io.Copy`, `http.MaxBytesReader`), verifies the sender signature,
  atomically renames it to the group's **latest** item, notifies other devices. GET serves from disk.
  → relay memory ≈ one buffer per request; disk ≤ cap × groups.
- **Limits:** cap **32 MiB** ciphertext (configurable, must stay < ⏳ Cloudflare 100 MB request limit);
  **TTL 10 min**; replaced items deleted immediately.
- **P2P is deferred**, cheap to add later because blobs are already E2E-encrypted and signed — only the
  fetch path changes: P2P-1 same-LAN mDNS direct GET; P2P-2 pion/webrtc + TURN-over-TLS on a host
  *not* behind the Tunnel (Cloudflare Tunnel cannot carry UDP/TURN). Neither helps the NordLayer laptop.

## 5. Identity, pairing, relay auth (ADR-004…007)
- **Device keys:** X25519 (age identity) + Ed25519 (signing), generated locally, stored in the OS keychain
  (zalando/go-keyring; 0600 file fallback on headless Linux). `device_id = SHA-256(ed25519_pk)[:16]`.
- **Sync group:** random 128-bit `group_id` + **roster** `{device_id, name, x25519_pk, ed25519_pk, added_by,
  added_at}`, monotonic `version`, signed by a current member. All devices are equal. Roster is stored on
  the relay **encrypted** (opaque blob).
- **Create:** `ecb init --relay https://…` — relay requires a server-side enrollment secret
  (`ECB_ENROLL_TOKEN`) to create a group → strangers can't use your relay.
- **Add device (pairing):**
  1. Paired device: `ecb pair` → relay opens a single-use mailbox (5 min, **one** PAKE attempt).
  2. It shows a code like `7-orbit-velvet-candle` (mailbox nr + 3 words ≈ 33 bits).
  3. New device: `ecb join 7-orbit-velvet-candle`. Both run PAKE (schollz/pake v3) via the mailbox, then
     **mutual key confirmation** `HMAC(K, "ecb-pair-v1"‖role‖transcript)` — the lib lacks it, we add it.
  4. New device sends its descriptor under K; existing device signs roster v+1, returns it under K,
     and sends a signed `AddDevice` to the relay.
  - Security: relay/Cloudflare get **one online guess (~2⁻³³)** per pairing; no offline brute force;
    a MITM relay fails key confirmation.
- **Relay auth:** challenge–response — device signs `"ecb-auth-v1"‖nonce‖group_id` with Ed25519 → short-lived
  session token. Relay keeps allowed Ed25519 keys per group; changes only on member-signed requests.
  Per-device rate limits. Only unauthenticated endpoint = an already-opened pairing mailbox.
- **Revoke:** `ecb devices rm <name>` → signed roster v+1 + signed `RemoveDevice`; relay drops the key at once;
  new items are no longer encrypted to it.

## 6. Payload format (ADR-008, 009)
Inner plaintext (inside age):
```
ctype u8 (1=text/utf-8, 2=image/png) | comp u8 (0=none, 1=zstd) | raw_len u64 | body
```
- zstd per item (klauspost/compress), never across items (compression side channel); skip for PNG.
- Receiver enforces `raw_len ≤ 256 MiB` before decompressing (zip-bomb guard).

Encryption: **age v1 binary**, recipients = all roster devices (one file key, N wraps, STREAM
ChaCha20-Poly1305, 64 KiB chunks, truncation-safe).

Outer frame v1 (big-endian, readable by relay):
```
magic "ECB1"(4) | ver u8=1 | flags u8 | group_id[16] | sender_id[16] | counter u64 | created_ms i64
| ct_len u64 | age_ciphertext[ct_len] | sig[64]
sig = Ed25519(sender_sk, "ecb-item-v1" ‖ header_bytes ‖ SHA-256(age_ciphertext))
```
- **Sender auth:** age has none → detached Ed25519 signature, checked by relay (before storing) and receiver
  (before decrypting).
- **Replay:** per-sender monotonic `counter`; receivers drop `≤ last seen`; items older than TTL+5 min dropped.
- No JSON/base64 anywhere on the data path.

## 7. Clipboard (ADR-010)
- Desktop: golang.design/x/clipboard `Watch` (text + PNG). ⏳ cgo need on darwin/linux unverified → check at M4.
- **Loop prevention:** ignore watch events whose `SHA-256(ctype‖raw)` equals the last applied or last sent
  item; 300 ms debounce.
- Per-device mode: `both | send-only | receive-only | paused` (important for the work laptop / DLP).
- **Mobile deferred:** iOS (no background reads, "Allow Paste" prompt) and Android 10+ (focused app / IME
  only) → later as foreground share/paste + tap-to-copy notifications, with QR pairing.

## 8. Repo layout (planned)
```
cmd/ecb/  cmd/ecb-relay/
internal/frame/     # binary frame v1 encode/decode
internal/envelope/  # zstd + age + Ed25519 sig + replay
internal/pairing/   # PAKE + key confirmation + mailbox protocol
internal/roster/    # signed roster
internal/keystore/  # OS keychain
internal/relay/     # server: auth, spool, TTL, notify
internal/transport/ # ws + longpoll client
internal/clip/      # clipboard watch/apply, loop prevention
internal/client/    # daemon wiring
test/integration/   # in-process relay + 2 clients
```

## 9. Milestones
| M | Scope | Accept when | Review |
| --- | --- | --- | --- |
| **M0** | Throwaway relay (`/ws` echo + PUT/GET 30 MB) behind the real Tunnel, run from the NordLayer laptop with VPN on | DNS ok; WS alive 10 min with 25 s pings; 30 MB up/down byte-identical; note cert issuer (TLS inspection?) | — |
| M1 | frame + envelope | round-trip text/PNG, multi-recipient; tampered header/ct/sig, wrong sender, replay, truncation, zstd bomb rejected; fuzz parser | **mandatory** |
| M2 | relay + transport | in-process relay + 2 clients: 20 MB A→B identical; relay heap growth < 8 MiB; expired → 404; oversize → 413 | recommended |
| M3 | identity, pairing, roster, relay auth | pairing ok; wrong code fails & mailbox burned; MITM relay fails confirmation; unauth device rejected; revocation immediate | **mandatory** |
| M4 | desktop daemon | 10k lines + screenshot each way < 3 s across macOS, work laptop, 1 more OS; no loops | optional |
| M5 | hardening | long-poll fallback, backoff, pause, size notice, content-free logs | optional |

Later: LAN P2P, mobile + QR, hotkey mode, size padding, key rotation.

## 10. Open questions (owner: user)
See `.agent-context/CURRENT.md` → "Open questions".
