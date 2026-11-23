# ADR-004 Per-device long-lived X25519 + Ed25519 keys in OS keychain
Status: accepted · 2026-11-23

**Decision:** each device generates X25519 (age identity) + Ed25519 (signing). device_id = SHA-256(ed25519_pk)[:16]. Stored via zalando/go-keyring; 0600 file fallback on headless Linux.
**Consequences:** no forward secrecy for items (accepted for MVP; key rotation later). Reference prototype regenerated keys per run and never verified signatures — fixed here.

**As built (2026-11-23):** backend policy `auto|keychain|file` (`ECB_KEYSTORE`); a failing keychain never
creates or overwrites an identity; plaintext file only with `AllowFileFallback` / file backend (loud warning).
State is protected by a cross-process file lock; roster in state only ever moves to a higher version.
