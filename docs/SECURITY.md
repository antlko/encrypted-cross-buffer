# ecb - security model

A concise statement of what `ecb` protects, what it does not, and what you must assume. The engineering detail (byte formats, diagrams, threat-model table) is in [TECHNICAL.md](TECHNICAL.md); operational hardening is in [OPERATIONS.md](OPERATIONS.md#hardening). *This project has not been independently audited.*

## Reporting a vulnerability

Please **open a private security advisory on GitHub** for this repository (Security tab, "Report a vulnerability"). Do not file public issues for security problems. Include the version or commit, what you did, what you expected, and what happened. This is a placeholder process for a small project: there is no bug bounty and no guaranteed response time.

## Security goals

1. **Confidentiality of clipboard content** against the relay operator, Cloudflare, network observers and TLS-inspecting proxies. The relay never holds a key that can decrypt an item.
2. **Authenticity of items**: an item is accepted only if signed by a device that is in the group's roster, and it is verified **before** it is decrypted.
3. **Integrity of membership**: devices can be added or removed only with a signature by an existing member; the relay cannot change the group on its own.
4. **No replay**: an old item cannot be applied again.
5. **Safe pairing** with a short code, with at most one online guess per pairing.

## What is protected

| Property | How |
| --- | --- |
| Content and content type | Encrypted with age to every other device's X25519 key; type and size of the plaintext are inside the ciphertext (the ciphertext length is visible). |
| Sender authenticity and integrity | Ed25519 signature over the frame header and the SHA-256 of the ciphertext; the receiver verifies before decrypting. |
| Membership | Signed, versioned roster; retained entries are immutable between versions; only a current member can sign the next version. |
| Replay and stale items | Per-sender strictly increasing counter, plus a timestamp window of TTL + 5 minutes (and at most 5 minutes in the future). |
| Pairing secrecy | PAKE (P-256) plus mutual key confirmation; the relay sees only opaque messages; a mailbox is single use. |
| Relay access | Ed25519 challenge-response, short-lived bearer tokens (15 min), per-IP and per-device rate limits; group creation needs the server-side enroll token. |
| Resource abuse | 32 MiB ciphertext cap, streaming relay, exact-length decompression with a cap, per-type limits, UTF-8 and PNG-signature checks. |
| Keys at rest | OS keychain by default; otherwise a 0600 file that is refused if group- or world-accessible (Unix). |
| Password-manager secrets | Items flagged sensitive by the copying app are never synced. |

## What is NOT protected

- **Metadata.** The relay and Cloudflare see: the group id, the device public keys and their number, which device sent each item and when, item sizes, the destination and IP addresses, and the timing of devices coming online. There is no padding or cover traffic.
- **Forward secrecy.** Items are encrypted to long-lived device keys. If a device key is ever stolen, previously captured ciphertext for that device can be decrypted. Key rotation is not implemented.
- **A compromised member device.** It reads every future item, can add attacker devices and remove yours. Recovery is removing it from a clean device and treating everything copied meanwhile as exposed. A stolen key also exposes already-captured ciphertext (see above).
- **The local machine.** Anything on the OS clipboard is readable by other programs of the same user. Malware, a compromised OS, or a user who can read your keychain defeats the model.
- **Availability.** The relay (or anyone controlling the network) can drop or delay items, or deny pairing. Only the latest item per group is kept, for 10 minutes.
- **Sensitive-flag reliance.** Whether a password manager's copy is skipped depends on that app setting the OS "sensitive/concealed" marker. Other apps are not filtered; use `ecb pause` when working with secrets, or `receive-only` / `send-only` on exposed machines.
- **Post-quantum attackers.** X25519 and Ed25519 are not quantum-resistant.
- **Replay after local state loss.** Counters are stored on each device; wiping a device's state resets them.
- **Plain-HTTP relay URLs.** Items stay encrypted, but the enroll token, tokens and metadata are then visible to the network. `ecb init` and `ecb join` therefore refuse `http://` to non-local hosts unless you pass `--insecure`; use HTTPS.

## Assumptions

- The device operating systems, their keychains and the `ecb` binary you built are not compromised.
- The random number generator of the OS is sound (keys, nonces and pairing words depend on it).
- The three-word pairing code is shown only to you and typed within its 5-minute lifetime; the generated code has 33 bits of entropy and is protected by the one-guess rule, not by length. If you choose your own code with `--code`, you own its strength.
- Your devices' clocks are within a few minutes of each other (the replay window).
- You trust the people who can physically use your unlocked devices.
- The relay host is kept updated; it is untrusted for confidentiality but its availability matters.

## Crypto inventory

Versions are from `go.mod` at the time of writing.

| Purpose | Primitive | Implementation |
| --- | --- | --- |
| Item encryption | age v1 binary format: X25519 recipient wrapping, ChaCha20-Poly1305 STREAM payload (64 KiB chunks) | `filippo.io/age` v1.3.2 |
| Item and roster signatures, relay auth, group creation | Ed25519 | Go standard library `crypto/ed25519` (Go 1.26) |
| Hashing (ciphertext digest, device id, token storage, enroll-token compare) | SHA-256 | Go standard library `crypto/sha256` |
| Pairing key agreement | PAKE (PAKE2-style) on P-256 | `github.com/schollz/pake/v3` v3.2.1 |
| Pairing key derivation | HKDF-SHA256 | `golang.org/x/crypto` v0.55.0 (`hkdf`) |
| Pairing key confirmation | HMAC-SHA256 | Go standard library `crypto/hmac` |
| Pairing message encryption | XChaCha20-Poly1305 | `golang.org/x/crypto` v0.55.0 (`chacha20poly1305`) |
| Sealed roster | age, to all roster members | `filippo.io/age` v1.3.2 |
| Compression (text only, before encryption) | Zstandard | `github.com/klauspost/compress` v1.20.5 |
| Randomness | OS CSPRNG | Go standard library `crypto/rand` |
| Pairing word list | BIP-39 English list, 2048 words | embedded (`internal/pairing/wordlist.txt`, see `NOTICE`) |
| Key storage | macOS Keychain, Windows Credential Manager, Linux Secret Service, or 0600 file | `github.com/zalando/go-keyring` v0.2.8 |
| Transport | TLS 1.2+ (terminated by Cloudflare or your proxy), HTTP/2, WebSocket | Go standard library, `github.com/coder/websocket` v1.8.15 |
| Clipboard access | OS pasteboard APIs | `golang.design/x/clipboard` v0.11.0 |
| Misc | terminal password prompt, OS calls | `golang.org/x/term` v0.48.0, `golang.org/x/sys` v0.50.0 |

CI runs `go vet`, the test suite with the race detector, and `govulncheck` on every push.

## Operational security checklist

- Use `https://` relay URLs and the default OS keychain.
- Treat `.env` (enroll and tunnel tokens) as secret; rotate the enroll token after setup.
- Never publish the relay container's port; keep `ECB_TRUST_PROXY_HEADERS` correct.
- Remove lost or retired devices at once with `ecb devices rm`.
- Use `receive-only` or `send-only` on machines with data-loss-prevention policies, and follow your employer's rules.
- Update the relay and the clients when security fixes are released.
