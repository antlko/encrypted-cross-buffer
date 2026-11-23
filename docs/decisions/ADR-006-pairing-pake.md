# ADR-006 Pairing: one-time code + PAKE with mutual key confirmation
Status: proposed · 2026-11-23 · open question: generated vs user-chosen code

**Decision:** a paired device runs 'ecb pair' → relay opens single-use mailbox (5 min, one attempt) → shows code like 7-orbit-velvet-candle (~33 bits). New device 'ecb join <code>'. schollz/pake v3 (PAKE2) through the mailbox + our mutual key confirmation HMAC(K,'ecb-pair-v1'‖role‖transcript). Then descriptor/roster exchanged under K.
**Why:** user-friendly short code yet relay/Cloudflare get only one online guess, no offline brute force; MITM relay fails confirmation. A long-lived shared passphrase would be offline-brute-forceable → rejected. CPace rejected (experimental). QR pairing added with mobile.
**To verify before M3:** pake v3 curve/API, no built-in confirmation.
