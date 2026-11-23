# ADR-007 Relay auth: enrollment secret per group + Ed25519 challenge-response per device
Status: proposed · 2026-11-23

**Decision:** creating a group needs server-side ECB_ENROLL_TOKEN (once). Every session: device signs 'ecb-auth-v1'‖nonce‖group_id → short-lived token. Relay keeps allowed Ed25519 keys per group, changed only by member-signed requests. Per-device rate limits. Only unauthenticated endpoint: an opened pairing mailbox.
**Why:** strangers can't use/DoS the relay; relay learns no secrets. Optional later: Cloudflare Access service tokens.
