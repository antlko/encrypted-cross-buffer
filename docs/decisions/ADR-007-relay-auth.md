# ADR-007 Relay auth: enrollment secret per group + Ed25519 challenge-response per device
Status: accepted · 2026-11-23

**Decision:** creating a group needs server-side ECB_ENROLL_TOKEN (once). Every session: device signs 'ecb-auth-v1'‖nonce‖group_id → short-lived token. Relay keeps allowed Ed25519 keys per group, changed only by member-signed requests. Per-device rate limits. Only unauthenticated endpoint: an opened pairing mailbox.
**Why:** strangers can't use/DoS the relay; relay learns no secrets. Optional later: Cloudflare Access service tokens.

**As built (2026-11-23):** `POST /v1/auth/token` also carries the `nonce`. Client IP for rate limiting comes
only from `CF-Connecting-IP`, parsed with `netip` (no DNS), and only when `ECB_TRUST_PROXY_HEADERS=true`.
Limiter maps are capped (LRU). Never publish the relay port when that flag is true.
