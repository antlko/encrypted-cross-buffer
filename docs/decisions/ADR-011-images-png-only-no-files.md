# ADR-011 Small images: PNG as-is; no file transfer in MVP

Status: accepted · 2026-11-23 (user: "no files for now, maybe a separate P2P file-transfer feature; small images like screenshots yes")

**Decision**
- Clipboard items are `text/utf-8` or `image/png`. Nothing else. No file/folder transfer.
- Images are sent **as PNG bytes unchanged** (no re-encode, no zstd: PNG is already deflate-compressed).
- Client-side image cap: **8 MiB** (configurable `max_image_bytes`); larger images are refused with a notice.
  Relay cap stays 32 MiB ciphertext (text can be big, ~1 MB text -> ~100-300 KB zstd).

**Why PNG**
- Screenshots (flat colours, sharp text) are what PNG is best at; macOS/Windows/Linux clipboard APIs
  expose PNG (or something trivially converted to it); golang.design/x/clipboard returns PNG.
- JPEG is lossy and bad for UI/text screenshots; WebP/AVIF need cgo or heavy deps and are not what the
  OS clipboard hands us anyway. Re-encoding costs CPU and risks quality loss for no big win at <=8 MiB.

**Later (separate feature, own ADR):** large files / big images via direct P2P transfer (LAN mDNS, then
WebRTC), reusing the same signed+age-encrypted envelope.

**Consequences:** `ctype` 1=text, 2=image/png only; unknown ctype is rejected by receivers.
