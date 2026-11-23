# ADR-008 Payload: age multi-recipient + detached Ed25519 signature + counter
Status: accepted · 2026-11-23

**Decision:** age v1 binary to all roster X25519 keys (one file key, STREAM ChaCha20-Poly1305 64 KiB chunks). Detached Ed25519 sig over header ‖ SHA-256(ciphertext), checked by relay and receiver. Per-sender monotonic u64 counter for replay; items older than TTL+5 min dropped.
**Alternatives:** custom X25519+XChaCha20 STREAM (re-implements age, more risk); NaCl box per device (N× payload); Noise sessions (no store-and-forward fit).
