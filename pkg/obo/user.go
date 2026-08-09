package obo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// UserIssuer simulates an Identity Provider (IdP) that issues user identity tokens.
// In production this is Entra ID, Auth0, Okta, or any OIDC-compliant IdP.
type UserIssuer struct {
	issuerID string
	key      *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewUserIssuer creates a UserIssuer.
//
//   - issuerID: the IdP's issuer URL (iss claim)
//   - key: signing key
//   - ttl: token lifetime; zero uses 60 minutes
func NewUserIssuer(issuerID string, key *ecdsa.PrivateKey, ttl time.Duration) *UserIssuer {
	if ttl == 0 {
		ttl = defaultUserTTL
	}
	return &UserIssuer{issuerID: issuerID, key: key, ttl: ttl}
}

// Issue creates a user identity token for the given subject.
//
//   - sub: user's unique identifier (e.g. "user:alice@example.com")
//   - email: user's email address
//   - scope: space-separated list of OAuth scopes the user has consented to
//   - audience: intended recipient (e.g. the OBO AS endpoint)
func (u *UserIssuer) Issue(sub, email, scope, audience string) (string, error) {
	if sub == "" {
		return "", errors.New("sub is required")
	}
	if audience == "" {
		return "", errors.New("audience is required")
	}

	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    u.issuerID,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(u.ttl)),
			ID:        base64.RawURLEncoding.EncodeToString(jtiRaw),
		},
		Scope: scope,
		Email: email,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = UserTokenType
	return t.SignedString(u.key)
}

// UserValidator validates user tokens issued by a specific IdP.
// Resource servers and OBO issuers use this to verify the user's identity.
type UserValidator struct {
	issuerID string
	pubKey   *ecdsa.PublicKey
	parser   *jwt.Parser
}

// NewUserValidator creates a UserValidator.
//
//   - issuerID: the expected iss value (the IdP's URL)
//   - pubKey: the IdP's ECDSA public signing key
func NewUserValidator(issuerID string, pubKey *ecdsa.PublicKey) *UserValidator {
	return &UserValidator{
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

// Validate verifies a user token's signature, expiry, issuer, and typ header.
// audience is the expected aud value (the OBO AS endpoint URL).
func (v *UserValidator) Validate(token, audience string) (*UserClaims, error) {
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

	claims := &UserClaims{}
	t, err := p.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != UserTokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, UserTokenType)
		}
		return v.pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate user token: %w", err)
	}
	if !t.Valid {
		return nil, errors.New("user token invalid")
	}
	return claims, nil
}
