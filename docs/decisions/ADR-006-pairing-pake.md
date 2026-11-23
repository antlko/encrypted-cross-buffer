# ADR-006 Pairing: one-time code + PAKE with mutual key confirmation
Status: accepted · open question: generated vs user-chosen code

**Decision:** a paired device runs 'ecb pair' → relay opens single-use mailbox (5 min, one attempt) → shows code like 7-orbit-velvet-candle (~33 bits). New device 'ecb join <code>'. schollz/pake v3 (PAKE2) through the mailbox + our mutual key confirmation HMAC(K,'ecb-pair-v1'‖role‖transcript). Then descriptor/roster exchanged under K.
**Why:** user-friendly short code yet relay/Cloudflare get only one online guess, no offline brute force; MITM relay fails confirmation. A long-lived shared passphrase would be offline-brute-forceable → rejected. CPace rejected (experimental). QR pairing added with mobile.
**To verify before M3:** pake v3 curve/API, no built-in confirmation.

**As built (2026-11-23):** PAKE curve `p256` via `pake.InitCurveWithIdentities` (identities `ecb-pair-v1|<mailbox>`).
Mutual HMAC confirmation runs BEFORE anything is published. The joiner receives a roster of version >= 2, so
`roster.Verify(nil)` (genesis only) cannot be used: `internal/pairing` has `verifyBootstrapRoster`, trusted
only because the roster arrives over the authenticated PAKE+AEAD channel. Mailbox ids are 1..99 and global.
Unauthenticated burning of mailboxes is a known DoS (rate-limited per IP; no confidentiality impact).

**Wording correction:** the confirmation key is derived with HKDF from the PAKE key
(`info "ecb-pair-keys-v1"`) and the MACs are `HMAC-SHA256(confirmKey, "ecb-confirm-A|B" || len-prefixed transcript)`;
the PAKE is `schollz/pake/v3` on P-256 (not "PAKE2 on siec"). The earlier `HMAC(K, 'ecb-pair-v1'||role||transcript)`
formula in this ADR is superseded by this paragraph.
