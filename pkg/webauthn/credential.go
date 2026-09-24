// Package webauthn simulates a WebAuthn Level 4 passkey in pure Go.
//
// In a real browser the private key never leaves the authenticator chip.
// This package models the same cryptographic properties in-process so demos
// and tests can run without a browser or hardware authenticator.
package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Credential represents a simulated WebAuthn passkey (P-256, ES256).
type Credential struct {
	// ID is a base64url-encoded random 16-byte credential identifier.
	ID string
	// PublicKey is the verification key; share with relying parties.
	PublicKey *ecdsa.PublicKey
	// UserID is the user handle stored at registration time.
	UserID string

	privateKey *ecdsa.PrivateKey
	prfSecret  []byte // 32-byte HMAC key for PRF extension simulation
}

// Register generates a new passkey for userID.
// Equivalent to navigator.credentials.create() in a browser.
func Register(userID string) (*Credential, error) {
	if userID == "" {
		return nil, errors.New("userID must not be empty")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Credential ID: 16 random bytes, base64url-encoded.
	rawID := make([]byte, 16)
	if _, err := rand.Read(rawID); err != nil {
		return nil, err
	}

	// PRF secret: 32 random bytes.
	prfSecret := make([]byte, 32)
	if _, err := rand.Read(prfSecret); err != nil {
		return nil, err
	}

	return &Credential{
		ID:         base64.RawURLEncoding.EncodeToString(rawID),
		PublicKey:  &priv.PublicKey,
		UserID:     userID,
		privateKey: priv,
		prfSecret:  prfSecret,
	}, nil
}
