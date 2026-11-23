# Research: transport, NAT traversal, corporate VPN, Cloudflare Tunnel

Date: 2026-11-23 · Status: initial research (researcher agent, spot-checked by orchestrator).
Facts marked ⏳ go stale (versions, limits) — re-verify before relying on them.

## Verdict
Direct P2P is an **optional optimisation**, never the only path. The **mandatory path is an outbound
WebSocket over HTTPS 443 to our own relay** (behind Cloudflare Tunnel). The corporate (NordLayer) laptop
will almost certainly always use the relay.

## Why Tailscale/LAN failed on the work laptop (hypothesis, not diagnosed)
- NordLayer kill switch blocks LAN traffic by default; local-network access is an admin per-team setting;
  DNS-leak protection also blocks outgoing DNS. (help.nordlayer.com/docs/kill-switch — search summary only)
- Tailscale DERP itself works over HTTPS 443 even when UDP is blocked (tailscale.com/kb/1082/firewalls),
  so the failure is most likely NordLayer LAN/route/DNS policy or a second WireGuard client conflict
  (100.64.0.0/10 overlap) — [unverified].
- Consequence: anything that needs inbound connectivity, LAN reachability or a second VPN on that laptop is out.

## Options considered for P2P
| Option | Status | Verdict |
| --- | --- | --- |
| pion/webrtc + pion/ice + pion/turn (Go) | ⏳ pion/turn v4.1.4 (Jan 2026) has TCP/TLS listeners → TURN over TLS 443 possible; RFC 6062 TCP allocations "planned" | Best Go fit **if** P2P is ever added; TURN must be on a host NOT behind Cloudflare Tunnel |
| iroh (Rust) | Official bindings Python/Swift/Kotlin/Node; Go binding community-only | Reject for Go core; reconsider only for a Rust rewrite |
| go-libp2p (hole punching + circuit relay v2) | Not verified (sources unavailable) | Heavy; reject unless needed |
| tailscale tsnet + derper + headscale | ⏳ tsnet v1.104.x: linux/windows/darwin/wasm, no mobile | Reject: no mobile, control plane, already failed on work laptop |
| Same-LAN mDNS (hashicorp/mdns, grandcat/zeroconf) | Not verified | Later, desktop-only optimisation; useless for the NordLayer laptop |

## Cloudflare Tunnel constraints
- Public hostnames carry **HTTP/WebSocket only**; arbitrary TCP needs cloudflared/WARP on the client;
  UDP/TURN not possible (Spectrum = Enterprise). [established/unverified mix]
- ⏳ Request body > **100 MB → 413** on Free/Pro. Chunk large payloads; cap item size.
- ⏳ WebSocket idle timeout ~100 s (third-party reports) → app ping every ≤30 s.
- cloudflared default `--protocol auto` (QUIC → HTTP/2 fallback).
- **Cloudflare terminates TLS** → it sees plaintext of whatever we send → all content and key material must
  be E2E encrypted at the application layer; treat Cloudflare + our server as untrusted relays.
- ToS for large non-HTML traffic on Free plan: not verified; low risk for personal clipboard volume.

## Must verify on the work laptop (first real-world test)
1. Outbound HTTPS 443 to the Tunnel hostname resolves and connects (DNS via NordLayer).
2. WebSocket upgrade survives any corporate proxy / TLS inspection. If not → fallback to HTTP long-poll /
   chunked POST over plain HTTPS (design the protocol so transport is swappable).

## Sources
- https://tailscale.com/kb/1082/firewalls · https://tailscale.com/docs/reference/connection-types
- https://help.nordlayer.com/docs/kill-switch
- https://pkg.go.dev/github.com/pion/turn/v4 · https://pkg.go.dev/tailscale.com/tsnet
- https://github.com/n0-computer/iroh-ffi · https://docs.iroh.computer/iroh-services/relays/self-hosted.md
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/run-parameters/
