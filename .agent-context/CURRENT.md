# CURRENT — encrypted-cross-buffer

## Request (2026-11-23)
Initial research + agent infrastructure + base docs so future sessions don't re-research.
Cross-platform E2EE clipboard sync based on Curve25519 (reference: github.com/antlko/go-e2ee-chat).

## User requirements
1. One laptop on corporate NordLayer VPN; unreachable via LAN/Tailscale. Must still work.
2. Large texts (10k+ lines) and images; efficient encode/decode.
3. Own server + Cloudflare Tunnel; nobody outside learns anything; user-friendly + secure device login.
3.1 Research: direct device-to-device to avoid streaming through / clogging the server.
4. Global `team-workflow` skill.

## Status
- DONE: research (docs/research/*), architecture (docs/ARCHITECTURE.md), ADR-001…010 (proposed),
  CLAUDE.md, global skill ~/.claude/skills/team-workflow/SKILL.md.
- NEXT: M0 — connectivity smoke test from the NordLayer laptop (WS 10 min + 30 MB PUT/GET via Tunnel).
- Before M3: verify schollz/pake v3 curve/API. Before M4: verify golang.design/x/clipboard cgo needs.

## Open questions (user)
1. Pairing code: generated one-time (recommended) vs user-invented (`--code` override)?
2. Work laptop policy/DLP: default mode both vs send-only/receive-only?
3. Limits: 32 MiB cap, 10 min TTL — OK?
4. Images in MVP: PNG only — OK?
