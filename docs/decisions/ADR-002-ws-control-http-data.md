# ADR-002 Control over WebSocket, data over HTTP PUT/GET
Status: proposed · 2026-11-23

**Decision:** WS /v1/ws carries tiny JSON notifications only, 25 s client ping, jittered backoff. Items move as one binary blob via PUT/GET /v1/items/{id}. Control channel behind an interface; long-poll GET /v1/events?after=<seq> fallback if a corporate proxy breaks WS (built in M2 if M0 fails, else M5).
**Why:** keeps big payloads off the WS (no framing/backpressure issues, plain HTTPS survives proxies), relay can stream to disk.
**Consequences:** two endpoints to authenticate; ⏳ Cloudflare ~100 s WS idle timeout unverified.
