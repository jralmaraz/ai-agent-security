package cb4a

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// generateID returns a 128-bit cryptographically random identifier.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("cb4a: generate ID: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// encodeBase64url encodes bytes as base64url without padding.
func encodeBase64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
