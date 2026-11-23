# Research: crypto, device pairing, large payloads, clipboard & key storage libs

Date: 2026-11-23 · Status: initial research (researcher agent, spot-checked by orchestrator).
⏳ = version/date facts that go stale; re-verify before pinning dependencies.

## Reference prototype (github.com/antlko/go-e2ee-chat) — what NOT to repeat
- X25519 public keys are exchanged **through the server with no authentication** → server (or Cloudflare,
  which terminates TLS) can MITM every pair. An Ed25519 signature is created but **never verified**, and the
  identity key is regenerated on every start (no persistent identity).
- HKDF with no salt/info; one static AES-GCM key per session, random 96-bit nonces (fine for low volume).
- JSON + `[]byte` → base64 (+33 %) on every message; whole message held in memory; no chunking.
- Room manager holds rooms in a slice behind a single goroutine — OK for a toy, no auth/rate-limit.

## Pairing ("log in" your devices)
| Option | Notes | Verdict |
| --- | --- | --- |
| QR code of device public key + fingerprint | Strongest, zero guessing, needs a camera/screen | **Primary** when a phone/camera is involved |
| PAKE with user-typed short code | Code can be low-entropy (6–8 words/digits) because PAKE allows only **online** guessing; one guess per attempt | **Primary** desktop↔desktop (e.g. the work laptop) |
| SAS compare | Human compares strings after unauthenticated DH | Fallback only |
| Long-lived shared passphrase as the key | Offline-brute-forceable by the relay | **Reject** |

Libs: ⏳ `github.com/schollz/pake/v3` v3.2.1 (MIT, used by croc) — PAKE2 without RFC 9382 key schedule or
key confirmation → **we must add explicit mutual key confirmation** (HMAC over transcript). `filippo.io/cpace`
is experimental (2021 pseudo-version) → reject. `psanford/wormhole-william` (magic-wormhole in Go) —
maintenance unverified; useful as design reference.

## Payload encryption
- **age v1** (`filippo.io/age`, C2SP spec): one random file key wrapped to N X25519 recipients; payload =
  STREAM ChaCha20-Poly1305, **64 KiB chunks**, counter nonces + last-chunk flag (truncation-safe); header MAC.
  Fits "one sender → all my devices, relay may store briefly".
- age has **no sender authentication** → add per-device Ed25519 signature (or rely on authenticated
  channel) so a device only accepts items from paired devices.
- `github.com/flynn/noise` ⏳ v1.1.0 (Feb 2024): good for live forward-secret sessions (IK/XX); more work for
  store-and-forward. Not needed for MVP.
- Raw NaCl box for fan-out → reject (N× encryption of payload).

## Large payload efficiency
- Binary framing (length-prefixed / raw body), **no JSON+base64** for payloads.
- Stream: never hold more than a few chunks in memory; 64 KiB chunk AEAD (age STREAM).
- Compression: ⏳ `github.com/klauspost/compress/zstd` v1.20.x (pure Go). Compress **each clipboard item
  separately** before encryption; skip already-compressed formats (PNG/JPEG). Compression-length side
  channel only matters if attacker-injected text shares a compressed stream with a secret — per-item
  compression avoids that. Relay always learns approximate size (optionally pad to buckets).
- AES-GCM vs ChaCha20 throughput not benchmarked; using age means ChaCha20-Poly1305 — fast enough
  (hundreds of MB/s+) for clipboard sizes. [opinion]

## Clipboard access
- Desktop: ⏳ `golang.design/x/clipboard` v0.11.x — text + image (PNG), no cgo required per docs, `Watch()`
  (event-driven on Wayland/Windows, 1 s polling elsewhere), Linux Wayland data-control or X11.
- `atotto/clipboard`: text-only, needs xclip/xsel on Linux → reject.
- **iOS**: no background clipboard reads; iOS 16+ shows "Allow Paste" prompt on programmatic read
  (UIPasteControl avoids it). → user-triggered / foreground only.
- **Android 10+**: only the focused app or default IME can read clipboard → foreground only (or custom keyboard).
- ⇒ Mobile = "push from phone via Share/paste button; receive as notification → tap to copy". Desktop = automatic.

## Key storage
- ⏳ `github.com/zalando/go-keyring` v0.2.8 (macOS `security`, Windows Credential Manager, Linux Secret Service).
- ⏳ `github.com/99designs/keyring` v1.2.2 (2022) — more backends incl. encrypted file (headless Linux).
- Mobile: native Keychain / Android Keystore.

## Sources
https://github.com/schollz/pake · https://pkg.go.dev/filippo.io/cpace · https://github.com/psanford/wormhole-william ·
https://github.com/C2SP/C2SP/blob/main/age.md · https://github.com/FiloSottile/age ·
https://pkg.go.dev/github.com/flynn/noise · https://pkg.go.dev/github.com/klauspost/compress/zstd ·
https://pkg.go.dev/golang.design/x/clipboard · https://developer.android.com/about/versions/10/privacy/changes ·
https://developer.apple.com/forums/thread/715328 · https://pkg.go.dev/github.com/zalando/go-keyring ·
https://pkg.go.dev/github.com/99designs/keyring · BREACH: https://css.csail.mit.edu/6.566/2014/readings/breach.pdf
