// Package relay implements the untrusted ecb relay: group registry, Ed25519
// challenge-response auth, a latest-only item spool, event notification
// (WebSocket + long-poll) and the pairing mailbox. It never sees plaintext;
// rosters are opaque blobs and item bodies are age ciphertext.
package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// Domain separators of the signed relay messages.
const (
	domGroupCreate = "ecb-group-create-v1"
	domRosterPub   = "ecb-roster-pub-v1"
	domAuth        = "ecb-auth-v1"
)

// GroupCreateMessage is signed by the creating device's Ed25519 key:
// "ecb-group-create-v1" || group_id || pub || SHA256(blob) || version(u64 BE).
func GroupCreateMessage(gid [16]byte, pub ed25519.PublicKey, blob []byte, version uint64) []byte {
	h := sha256.Sum256(blob)
	m := append([]byte(domGroupCreate), gid[:]...)
	m = append(m, pub...)
	m = append(m, h[:]...)
	return binary.BigEndian.AppendUint64(m, version)
}

// RosterPubMessage is signed by a current member when publishing a roster:
// "ecb-roster-pub-v1" || group_id || version(u64 BE) || SHA256(blob) || keys
// (each 32 bytes, sorted bytewise ascending, concatenated).
func RosterPubMessage(gid [16]byte, version uint64, blob []byte, keys []ed25519.PublicKey) []byte {
	h := sha256.Sum256(blob)
	m := append([]byte(domRosterPub), gid[:]...)
	m = binary.BigEndian.AppendUint64(m, version)
	m = append(m, h[:]...)
	sorted := make([][]byte, len(keys))
	for i, k := range keys {
		sorted[i] = k
	}
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })
	for _, k := range sorted {
		m = append(m, k...)
	}
	return m
}

// AuthMessage is signed to obtain a session token:
// "ecb-auth-v1" || nonce (raw bytes) || group_id.
func AuthMessage(nonce []byte, gid [16]byte) []byte {
	m := append([]byte(domAuth), nonce...)
	return append(m, gid[:]...)
}
