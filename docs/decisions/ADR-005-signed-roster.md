# ADR-005 Sync group with member-signed roster; all devices equal
Status: proposed · 2026-11-23

**Decision:** random 128-bit group_id; roster {device_id,name,x25519_pk,ed25519_pk,added_by,added_at}, monotonic version, signed by a current member, stored on relay encrypted. Devices accept only higher version signed by a current member. Revocation = signed v+1 without the device + signed RemoveDevice to relay.
**Accepted risk:** a compromised member can add/remove devices; recovery = re-init.
