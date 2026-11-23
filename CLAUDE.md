# encrypted-cross-buffer (ecb)

E2EE clipboard sync between one user's own devices (Go). Untrusted relay behind Cloudflare Tunnel;
content encrypted on device (X25519/age + Ed25519). **Status: design only, no code yet** (2026-11-23).

## Workflow
Non-trivial task → load the global `team-workflow` skill (researcher / adviser / developer / reviewer).
Check `docs/research/` and `docs/decisions/` **before** researching anything again.
Live task state: `.agent-context/CURRENT.md` (rewrite, don't append).

## Topic map (read only the slice you need)
| Topic | Where |
| --- | --- |
| Overall design, threat model, frame format, milestones | `docs/ARCHITECTURE.md` |
| Why relay-only / P2P later / Cloudflare & NordLayer limits | `docs/research/2026-11-23-transport-nat-cloudflare.md`, ADR-001…003 |
| Pairing, keys, roster, relay auth | ADR-004…007, `docs/research/2026-11-23-crypto-pairing-clipboard.md` |
| Payload crypto & binary format | ADR-008, ADR-009 |
| Clipboard libs, mobile limits, loop prevention | ADR-010, crypto research doc |
| Reference prototype (github.com/antlko/go-e2ee-chat) flaws | crypto research doc, first section |

## Invariants (never break without a new ADR)
1. Relay and Cloudflare are **untrusted**: never send plaintext content, content type, keys or pairing code to them.
2. Every public key exchange is **authenticated** (PAKE + key confirmation, or signed roster). No trust-on-relay.
3. Data path is **binary and streamed**; no JSON/base64 for payloads; relay never buffers a whole item in RAM.
4. Every item is **signed** (Ed25519) and replay-checked; verify before decrypt/store.
5. Compression only **per item**; enforce size caps before decompressing.
6. Logs never contain clipboard content or key material.
7. Use vetted libs (age, x/crypto, schollz/pake) — no home-made primitives.

## Commands
None yet (no go.mod). When added: `go test ./...`, `go vet ./...`, integration tests in `test/integration/`.

## Review
Reviewer is **mandatory** for anything under `internal/{frame,envelope,pairing,roster,keystore,relay}`,
wire-format or auth changes.
