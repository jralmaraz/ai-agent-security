// Package keys provides EC P-256 key pair generation and JWK serialization
// for the ai-agent-security identity layer.
package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// ECKeyPair holds an EC P-256 private/public key pair.
type ECKeyPair struct {
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

// JWK is a minimal JSON Web Key for EC P-256 (RFC 7517 §6.2).
// Alg is always "ES256" as required by the WIMSE workload-creds spec.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg"`
}

// GenerateECKeyPair generates a fresh EC P-256 key pair.
func GenerateECKeyPair() (*ECKeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC key: %w", err)
	}
	return &ECKeyPair{Private: priv, Public: &priv.PublicKey}, nil
}

// PublicKeyToJWK serializes an EC P-256 public key to a JWK.
// X and Y are left-padded to 32 bytes per RFC 7518 §6.2.
func PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) (*JWK, error) {
	if pub == nil {
		return nil, errors.New("nil public key")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("only P-256 is supported")
	}
	return &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   encodeCoord(pub.X),
		Y:   encodeCoord(pub.Y),
		Kid: kid,
		Alg: "ES256",
	}, nil
}

// JWKToPublicKey deserialises a JWK back to an *ecdsa.PublicKey.
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %q / curve %q", jwk.Kty, jwk.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decode X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decode Y: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(x, y) {
		return nil, errors.New("point is not on P-256 curve")
	}
	return pub, nil
}

// JWKFromRawMessage parses a json.RawMessage into a JWK.
func JWKFromRawMessage(raw json.RawMessage) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshal JWK: %w", err)
	}
	return &jwk, nil
}

// encodeCoord left-pads a big.Int to 32 bytes and base64url-encodes it.
func encodeCoord(n *big.Int) string {
	b := n.Bytes()
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		b = padded
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
