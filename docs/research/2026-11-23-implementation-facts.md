# Verified implementation facts (pake API, clipboard, cloudflared)

Date: 2026-11-23 · from source/pkg.go.dev. ⏳ = re-verify when bumping versions.

## schollz/pake/v3 (⏳ v3.2.1)
- API: `pake.InitCurve(pw []byte, role int, curve string)`, `InitCurveWithIdentities(pw, role, curve, idA, idB)`
  (v3.2.0+, binds identities into K), `Bytes()`, `Update(peerBytes) error`, `SessionKey()`, `HaveSessionKey()`.
- Role is an **int: 0 = party A, 1 = party B** (no constants). Curves are lowercase: `p256 p384 p521 siec ed25519`.
  Use **`p256`** (stdlib-backed, boring) unless a reason appears; `siec` is the README default.
- Flow: A.Bytes() -> B.Update(); B.Bytes() -> A.Update(); then both SessionKey(). 2 messages.
- **A wrong password is NOT detected**: Update returns nil and the keys silently differ. We MUST add mutual
  HMAC key confirmation over the transcript before trusting K.
- Gotchas: fresh `Pake` object per attempt; Update can be called twice and silently overwrites K (guard it);
  `SessionKey()`/`Bytes()` on a nil receiver panic; same role on both sides errors.

## golang.design/x/clipboard (⏳ v0.11.0, go 1.24)
- **No cgo** on darwin (purego), linux (pure-Go x11/wayland), windows. Builds with CGO_ENABLED=0.
- `Init() error` first (errors if no display). `Read(ctx, fmt)`, `Write(ctx, fmt, buf) (<-chan struct{}, error)`,
  `Watch(ctx) <-chan Data`; formats `FmtText` (UTF-8), `FmtImage` (PNG), `FmtFiles`.
- Watch polls 1/s on macOS and X11; event-driven on Wayland/Windows.
- **A running Watch emits an event for our own Write** -> loop prevention by content hash is mandatory (ADR-010).
- Linux runtime needs X server or Wayland data-control; headless CI: `xvfb`. The writer must keep running.

## Docker + cloudflared
- Sidecar: image `cloudflare/cloudflared`, `command: tunnel --no-autoupdate run`, env `TUNNEL_TOKEN`.
  Public hostname Service URL = `http://relay:8080` (compose network name). WebSockets work through Cloudflare
  proxy with no extra config; idle timeout undocumented -> app pings every 25 s.
- Dashboard (Zero Trust): Networking > Tunnels > Create Tunnel > pick Docker > copy token > run > Healthy >
  Routes > Add route > Published application > subdomain+domain, Service `http://relay:8080`. ⏳ labels may change.

## README style reference (github.com/antlko/learn-hungarian-ai)
Title+tagline, 4 badges, feature sections, "why", Quick start with one subsection per install method
("pick one"; Docker Compose first), optional components table, how it works, honest limits, docs links, licence.
Tone: confident, dry, short declarative sentences, no emoji. We add mermaid diagrams.
