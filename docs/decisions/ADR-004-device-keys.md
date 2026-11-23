# ADR-004 Per-device long-lived X25519 + Ed25519 keys in OS keychain
Status: proposed · 2026-11-23

**Decision:** each device generates X25519 (age identity) + Ed25519 (signing). device_id = SHA-256(ed25519_pk)[:16]. Stored via zalando/go-keyring; 0600 file fallback on headless Linux.
**Consequences:** no forward secrecy for items (accepted for MVP; key rotation later). Reference prototype regenerated keys per run and never verified signatures — fixed here.
