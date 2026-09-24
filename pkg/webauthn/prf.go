package webauthn

import (
	"crypto/hmac"
	"crypto/sha256"
)

// PRF simulates the WebAuthn Level 4 PRF extension.
//
// Real WebAuthn PRF: the authenticator computes HMAC(authData || clientDataJSON, input)
// using a key derived from the credential's private key. Here we use
// HMAC-SHA256(prfSecret, input) as a functionally equivalent simulation.
//
// The returned 32 bytes are deterministic for a given (credential, input) pair
// and suitable as a key derivation input (e.g. via HKDF).
func (c *Credential) PRF(input []byte) []byte {
	mac := hmac.New(sha256.New, c.prfSecret)
	mac.Write(input)
	return mac.Sum(nil)
}
