package webauthn

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// MakeAssertion signs challenge with the credential's private key.
// Returns the base64url-encoded raw 64-byte ECDSA P-256/SHA-256 signature
// (r||s, each 32 bytes big-endian) — the same encoding as RFC 9421 and FIDO2.
//
// Equivalent to navigator.credentials.get() in a browser.
func (c *Credential) MakeAssertion(challenge []byte) (string, error) {
	if len(challenge) == 0 {
		return "", errors.New("challenge must not be empty")
	}
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, c.privateKey, digest[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(rawSig(r, s)), nil
}

// VerifyAssertion checks that assertionB64 is a valid signature over challenge
// by the private key corresponding to pub.
func VerifyAssertion(pub *ecdsa.PublicKey, challenge []byte, assertionB64 string) error {
	if pub == nil {
		return errors.New("public key is required")
	}
	if len(challenge) == 0 {
		return errors.New("challenge must not be empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(assertionB64)
	if err != nil {
		return errors.New("invalid assertion encoding: " + err.Error())
	}
	if len(raw) != 64 {
		return errors.New("invalid assertion length: expected 64 bytes")
	}
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	digest := sha256.Sum256(challenge)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return errors.New("assertion signature verification failed")
	}
	return nil
}

// rawSig encodes r and s as a fixed-width 64-byte big-endian concatenation.
func rawSig(r, s *big.Int) []byte {
	out := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):64], sb)
	return out
}
