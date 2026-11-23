# ADR-001 Relay-only transport for MVP; P2P deferred
Status: accepted · 2026-11-23

**Context:** NordLayer work laptop has no inbound/LAN reachability (Tailscale failed); Cloudflare Tunnel carries HTTP/WS only, no UDP/TURN. See research/2026-11-23-transport-nat-cloudflare.md.
**Decision:** all devices connect outbound HTTPS 443 to our relay behind Cloudflare Tunnel. No P2P in MVP.
**Alternatives:** tsnet/headscale (no mobile, already failed), pion WebRTC+TURN (TURN can't sit behind Tunnel, never helps the work laptop), iroh (no official Go binding), libp2p (heavy).
**Consequences:** relay carries all bytes (bounded by cap/TTL). Later: P2P-1 same-LAN mDNS direct GET of the same signed blob; P2P-2 pion WebRTC + TURN-over-TLS on a non-Tunnel host.
