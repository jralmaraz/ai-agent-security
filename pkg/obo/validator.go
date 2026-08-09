package obo

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// OBOValidator is used by resource servers to validate OBO delegated tokens.
type OBOValidator struct {
	issuerID string
	pubKey   *ecdsa.PublicKey
	parser   *jwt.Parser
}

// ValidateResult holds the validated claims from an OBO token plus convenience accessors.
type ValidateResult struct {
	Claims  *OBOClaims
	// UserID is the human user's identity (sub claim).
	UserID  string
	// AgentID is the agent's identity (act.sub claim) — who is making the call.
	AgentID string
	// Scope is the granted scope string.
	Scope   string
}

// NewOBOValidator creates an OBOValidator.
//
//   - issuerID: the expected iss value (the OBO AS's identifier)
//   - pubKey: the OBO AS's ECDSA public signing key
func NewOBOValidator(issuerID string, pubKey *ecdsa.PublicKey) *OBOValidator {
	return &OBOValidator{
		issuerID: issuerID,
		pubKey:   pubKey,
		parser: jwt.NewParser(
			jwt.WithIssuer(issuerID),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithValidMethods([]string{"ES256"}),
		),
	}
}

// Validate verifies an OBO token and returns the delegation context.
//
// Checks performed:
//   - typ header == "obo+jwt"
//   - ES256 signature with the configured public key
//   - iss == configured issuerID
//   - aud contains audience
//   - exp not exceeded, iat present
//   - act.sub non-empty (agent identity)
//   - sub non-empty (user identity)
//
// audience is the resource server's own URL (must appear in the token's aud).
func (v *OBOValidator) Validate(token, audience string) (*ValidateResult, error) {
	if token == "" {
		return nil, errors.New("token is required")
	}

	p := jwt.NewParser(
		jwt.WithIssuer(v.issuerID),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)

	claims := &OBOClaims{}
	t, err := p.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != OBOTokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, OBOTokenType)
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate OBO token: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("OBO token invalid")
	}
	if claims.Subject == "" {
		return nil, errors.New("OBO token missing sub (user identity)")
	}
	if claims.Act == nil || claims.Act.Subject == "" {
		return nil, errors.New("OBO token missing act.sub (agent identity)")
	}

	return &ValidateResult{
		Claims:  claims,
		UserID:  claims.Subject,
		AgentID: claims.Act.Subject,
		Scope:   claims.Scope,
	}, nil
}
