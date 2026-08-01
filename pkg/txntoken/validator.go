package txntoken

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Validator validates Transaction Token JWTs.
type Validator struct {
	issuerID string
	pubKey   *ecdsa.PublicKey
}

// NewValidator creates a Validator for tokens signed by the given issuer.
func NewValidator(issuerID string, pubKey *ecdsa.PublicKey) *Validator {
	return &Validator{issuerID: issuerID, pubKey: pubKey}
}

// Validate parses and validates a compact Txn-Token string.
//
// Checks performed:
//   - typ header == "txntoken+jwt"
//   - ES256 signature with the configured public key
//   - iss == configured issuerID
//   - exp not exceeded
//   - txn claim present
func (v *Validator) Validate(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token string is required")
	}

	parser := jwt.NewParser(
		jwt.WithIssuer(v.issuerID),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"ES256"}),
	)

	claims := &Claims{}
	t, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != TokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, TokenType)
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate txn-token: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("txn-token is not valid")
	}
	if claims.Txn == "" {
		return nil, errors.New("txn-token missing required txn claim")
	}
	return claims, nil
}
