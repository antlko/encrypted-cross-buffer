# CURRENT - encrypted-cross-buffer

## Request (2026-11-23)
Build the complete app (desktop `ecb` + `ecb-relay`), deploy with docker compose behind Cloudflare Tunnel.
Docs in English, beginner-friendly install (style of github.com/antlko/learn-hungarian-ai), diagrams + full
technical docs. No secrets in git. Text + small PNG images only; files = future P2P feature. Use subagents.

## Status (end of session 1)
- DONE + committed: crypto core, relay, client lib, pairing (PAKE p256 + HMAC confirmation), daemon, CLI,
  `ecb doctor`, Docker/compose/CI, e2e script. Reviews: M1 core (fixed), full security review (fixed),
  re-review of fixes (see git log for result).
- Docs: README.md, docs/{TECHNICAL,OPERATIONS,SECURITY,ARCHITECTURE}.md, ADR-001..011 accepted + "As built".
- Verification run: gofmt, go vet, `go test ./... -race`, `make e2e` (3 processes, 10k lines < 1 s, no echo
  loop, revoke), docker build + compose local run healthy (image ~9 MB, nonroot, read-only FS).

## NOT verified yet (needs the user's machines)
1. Real Cloudflare Tunnel + the work laptop behind NordLayer: run `ecb doctor` there FIRST.
2. Real OS clipboard (macOS/Windows/Linux, `Sensitive` flag, PNG screenshots) and real keychain.
3. Windows/Linux daemon smoke. govulncheck: clean on Go 1.26.11 (go.mod pins `toolchain go1.26.11`; CI uses latest 1.26.x; x/image bumped).
4. CI workflow never ran on GitHub; actions/images pinned by tag, not digest.

## Backlog
Release binaries (goreleaser), P2P file transfer (LAN mDNS then WebRTC; own ADR), mobile (foreground share
+ QR pairing), key rotation (retained roster entries are immutable now), size padding, Cyrillic/NFC
homograph device names, optional Cloudflare Access service tokens.
