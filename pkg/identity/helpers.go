package identity

import (
	"crypto/rand"
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
