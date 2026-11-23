# encrypted-cross-buffer (ecb)

E2EE clipboard sync between one user's own devices (Go 1.26, pure Go, `CGO_ENABLED=0`).
`ecb` = desktop CLI/daemon, `ecb-relay` = untrusted relay deployed with Docker Compose behind a
Cloudflare Tunnel. **Status: implemented and reviewed (2026-11-23).** Text + small PNG images; no files, no mobile.

## Workflow
Non-trivial task -> load the global `team-workflow` skill (researcher / adviser / developer / reviewer).
Check `docs/research/` and `docs/decisions/` BEFORE researching again. Live state: `.agent-context/CURRENT.md`.
Keep the main context small: delegate reading/implementation to subagents.

## Commands
`make build` (-> ./bin) · `make test` / `make race` · `make vet` · `make fmt` · `make e2e` (3 real
processes, fake clipboards, temp dirs; never touches the real clipboard/keychain) · `make docker-build`.
Deploy: `docker compose --profile tunnel up -d --build`; local: `-f docker-compose.yml -f docker-compose.local.yml`.
Diagnose connectivity (corporate VPN): `ecb doctor`.

## Topic map (read only the slice you need)
| Topic | Where |
| --- | --- |
| Install, usage, troubleshooting (beginner) | `README.md` |
| Full technical deep-dive with diagrams | `docs/TECHNICAL.md` |
| Short as-built architecture, milestones | `docs/ARCHITECTURE.md` |
| Deploy, env vars, backup, runbook | `docs/OPERATIONS.md` |
| Threat model, crypto inventory | `docs/SECURITY.md` |
| Why each decision (accepted ADRs + "As built") | `docs/decisions/ADR-001..011` |
| Evidence: NAT/Cloudflare/NordLayer, crypto libs, verified API facts | `docs/research/*.md` |

## Package map
`internal/frame` outer binary frame + streaming signature verify · `envelope` zstd+age+sig+replay ·
`roster` signed device list · `keystore` identity/state (keychain, file fallback, lock) · `relay` server ·
`client` relay client (ws -> long-poll fallback) · `pairing` PAKE protocol · `daemon` sync loop ·
`clip` system/file clipboard · `doctor` diagnostics · `cmd/ecb`, `cmd/ecb-relay`.

## Invariants (never break without a new ADR)
1. Relay and Cloudflare are **untrusted**: never send plaintext content, content type, keys or pairing code.
2. Every public-key exchange is **authenticated** (PAKE + mutual key confirmation, or signed roster).
3. Data path is **binary and streamed**; no JSON/base64 for payloads; relay never buffers a whole item in RAM.
4. Every item is **signed** (Ed25519) and replay-checked; verify before decrypt/store.
5. Compression only **per item**; enforce size caps before decompressing; PNG never compressed.
6. Logs never contain clipboard content, tokens or key material.
7. Vetted libs only (age, x/crypto, schollz/pake) — no home-made primitives.
8. Sensitive-flagged clipboard items are never synced; a broken config never fails open.
9. Secrets never in git: `.env`, keys, tokens are ignored; only `.env.example` placeholders.

## Review
Reviewer is **mandatory** for changes in `internal/{frame,envelope,pairing,roster,keystore,relay,client,daemon}`,
wire format, auth, Docker/compose. Mutation-check new security tests on a COPY of the repo.
