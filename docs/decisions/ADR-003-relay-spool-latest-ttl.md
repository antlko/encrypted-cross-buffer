# ADR-003 Relay keeps latest item per group on disk, TTL 10 min, cap 32 MiB
Status: proposed · 2026-11-23

**Decision:** PUT streams to temp file (io.Copy + MaxBytesReader), signature verified, atomic rename to the group's latest item; replaced items deleted immediately; sweeper deletes after TTL 10 min. Cap 32 MiB ciphertext (configurable, must stay < ⏳ 100 MB Cloudflare request limit). No multi-request chunked upload in MVP.
**Why:** relay memory ≈ one buffer per request (answers 'don't clog server memory'); disk bounded by cap × groups; devices waking up shortly after still get the last item.
**Consequences:** no history; items > cap refused client-side with a notice.
