package identitychaining

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GrantValidator is the domain-B AS component that validates a JWT Authorization Grant
// issued by domain A and extracts the agent's SPIFFE ID.
type GrantValidator struct {
	// issuerID is the expected iss value — domain A's AS identifier.
	issuerID string
	// pubKey is domain A's public signing key.
	pubKey *ecdsa.PublicKey
}

// NewGrantValidator creates a GrantValidator.
//
//   - issuerID: the expected iss value (domain A's AS URL)
//   - pubKey: domain A's ECDSA public key (used to verify the grant signature)
func NewGrantValidator(issuerID string, pubKey *ecdsa.PublicKey) *GrantValidator {
	return &GrantValidator{issuerID: issuerID, pubKey: pubKey}
}

// Validate verifies a JWT Authorization Grant and returns its claims.
//
// Checks performed:
//   - typ header == "jwt-authz-grant"
//   - ES256 signature with the configured domain-A public key
//   - iss == configured issuerID
//   - aud contains tokenEndpoint
//   - exp not exceeded
//   - sub non-empty (SPIFFE ID of the agent)
//
// tokenEndpoint is domain B's token endpoint URL; it must appear in the grant's aud.
func (v *GrantValidator) Validate(grantToken, tokenEndpoint string) (*GrantClaims, error) {
	if grantToken == "" {
		return nil, errors.New("grant token is required")
	}
	if tokenEndpoint == "" {
		return nil, errors.New("token endpoint is required")
	}

	parser := jwt.NewParser(
		jwt.WithIssuer(v.issuerID),
		jwt.WithAudience(tokenEndpoint),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"ES256"}),
	)

	claims := &GrantClaims{}
	t, err := parser.ParseWithClaims(grantToken, claims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != GrantTokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, GrantTokenType)
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate grant: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("grant is not valid")
	}
	if claims.Subject == "" {
		return nil, errors.New("grant missing sub claim (agent SPIFFE ID)")
	}
	return claims, nil
}
