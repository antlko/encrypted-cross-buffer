# ADR-005 Sync group with member-signed roster; all devices equal
Status: accepted · 2026-11-23

**Decision:** random 128-bit group_id; roster {device_id,name,x25519_pk,ed25519_pk,added_by,added_at}, monotonic version, signed by a current member, stored on relay encrypted. Devices accept only higher version signed by a current member. Revocation = signed v+1 without the device + signed RemoveDevice to relay.
**Accepted risk:** a compromised member can add/remove devices; recovery = re-init.

## Amendment 2026-11-23
- Retained roster entries are immutable between versions: `Verify` requires every device present in both the held and the new roster to be identical in all fields (name, keys, added_by, added_at). A signer therefore cannot swap another member's keys or rename it. Key rotation, if ever needed, requires its own ADR.
- Genesis (no held roster) is trust-on-first-use. It is only safe if the roster arrives through the authenticated pairing channel (ADR-004), never via the relay. A stale holder also accepts rosters signed by a since-removed member; closing that needs relay-side enforcement.
