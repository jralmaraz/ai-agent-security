package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// generateJTI returns a 128-bit random string suitable for use as a JWT ID.
func generateJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns the base64url-encoded SHA-256 digest of a compact token string.
// Used to compute tth (Transaction Token Hash) in AgentProofClaims.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
