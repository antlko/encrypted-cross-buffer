# ADR-009 Binary frame v1 with per-item zstd
Status: proposed · 2026-11-23

**Decision:** outer: magic 'ECB1'|ver|flags|group_id[16]|sender_id[16]|counter u64|created_ms i64|ct_len u64|ct|sig[64]. Inner (inside age): ctype u8|comp u8|raw_len u64|body. zstd (klauspost/compress) per item only, skipped for PNG; receiver caps raw_len at 256 MiB.
**Why:** no JSON/base64 (+33 %) on the data path; per-item compression avoids the compression-length side channel across items; 10k lines ≈1 MB → ~100–300 KB (estimate).
