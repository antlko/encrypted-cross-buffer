# ADR-010 Desktop-only MVP with hash-based loop prevention
Status: accepted · 2026-11-23

**Decision:** golang.design/x/clipboard Watch (text + PNG) on macOS/Linux/Windows. Ignore events whose SHA-256(ctype‖raw) equals last applied/sent; 300 ms debounce. Per-device mode both|send-only|receive-only|paused.
**Why mobile later:** iOS forbids background reads (Allow Paste prompt), Android 10+ only focused app/IME. Later: foreground share/paste + tap-to-copy notification + QR pairing.
**To verify before M4:** cgo need on darwin/linux.
