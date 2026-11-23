package integration

import (
	"crypto/ed25519"

	"encoding/base64"
	"encoding/hex"
	"github.com/antlko/encrypted-cross-buffer/internal/keystore"
	"github.com/antlko/encrypted-cross-buffer/internal/relay"
)

func hexs(b []byte) string { return hex.EncodeToString(b) }
func b64d(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func signAuth(id *keystore.Identity, nonceB64 string, gid [16]byte) []byte {
	return ed25519.Sign(id.Ed25519, relay.AuthMessage(b64d(nonceB64), gid))
}

func b64e(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }
