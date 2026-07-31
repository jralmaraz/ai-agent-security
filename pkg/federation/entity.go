// Package federation implements OpenID Federation 1.0 entity configuration
// building, parsing, and trust-chain verification for WIMSE agent fabric gateways.
//
// OID-FED replaces static Validators maps with a cryptographically-chained
// discovery protocol: each agent IdP publishes a self-signed Entity Configuration JWT
// at /.well-known/openid-federation, and Trust Anchors publish Subordinate
// Statements that certify leaf entities' keys and metadata.
//
// References:
//   - https://openid.net/specs/openid-federation-1_0.html §4
//   - draft-ietf-wimse-arch-08 §6.2 (dynamic trust establishment)
package federation

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

const entityStatementTyp = "entity-statement+jwt"

// JWKS is an RFC 7517 JSON Web Key Set.
type JWKS struct {
	Keys []keys.JWK `json:"keys"`
}

// AgentIdPMetadata is the agent IdP subset used by WIMSE agent gateways.
type AgentIdPMetadata struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
}

// FederationEntityMetadata carries federation-layer endpoints.
type FederationEntityMetadata struct {
	FederationFetchEndpoint string `json:"federation_fetch_endpoint,omitempty"`
	OrganizationName        string `json:"organization_name,omitempty"`
}

// EntityMetadata groups role-specific metadata blocks.
type EntityMetadata struct {
	AgentIdP         *AgentIdPMetadata         `json:"agent_idp,omitempty"`
	FederationEntity *FederationEntityMetadata  `json:"federation_entity,omitempty"`
}

// EntityConfiguration is the payload of a self-signed Entity Configuration JWT
// (iss == sub). It advertises the entity's own JWKS and metadata, and hints
// at which Trust Anchors govern it.
type EntityConfiguration struct {
	Issuer         string          `json:"iss"`
	Subject        string          `json:"sub"` // == Issuer for self-signed
	IssuedAt       int64           `json:"iat"`
	ExpiresAt      int64           `json:"exp"`
	JWKS           JWKS            `json:"jwks"`
	Metadata       *EntityMetadata `json:"metadata,omitempty"`
	AuthorityHints []string        `json:"authority_hints,omitempty"`
}

// SubordinateStatement is the payload of a Subordinate Statement JWT issued
// by a superior (Trust Anchor or Intermediate) about a leaf entity.
type SubordinateStatement struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	IssuedAt  int64           `json:"iat"`
	ExpiresAt int64           `json:"exp"`
	JWKS      JWKS            `json:"jwks"` // leaf keys as trusted by the superior
	Metadata  *EntityMetadata `json:"metadata,omitempty"`
}

// BuildEntityConfiguration creates and signs an Entity Configuration JWT.
func BuildEntityConfiguration(
	issuerID string,
	signingKey *ecdsa.PrivateKey,
	kid string,
	orgName string,
	authorityHints []string,
	ttl time.Duration,
) (string, error) {
	pub, err := keys.PublicKeyToJWK(&signingKey.PublicKey, kid)
	if err != nil {
		return "", fmt.Errorf("serialize JWK: %w", err)
	}
	jwkMap, err := toMap(pub)
	if err != nil {
		return "", fmt.Errorf("convert JWK to map: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerID,
		"sub": issuerID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jwks": map[string]interface{}{
			"keys": []interface{}{jwkMap},
		},
		"metadata": map[string]interface{}{
			"agent_idp": map[string]interface{}{
				"issuer":         issuerID,
				"jwks_uri":       issuerID + "/.well-known/jwks.json",
				"token_endpoint": issuerID + "/agent/issue",
			},
			"federation_entity": map[string]interface{}{
				"federation_fetch_endpoint": issuerID + "/federation/fetch",
				"organization_name":         orgName,
			},
		},
	}
	if len(authorityHints) > 0 {
		hints := make([]interface{}, len(authorityHints))
		for i, h := range authorityHints {
			hints[i] = h
		}
		claims["authority_hints"] = hints
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = entityStatementTyp
	t.Header["kid"] = kid
	return t.SignedString(signingKey)
}

// BuildSubordinateStatement creates and signs a Subordinate Statement by a Trust
// Anchor about a leaf entity, certifying the leaf's public key.
func BuildSubordinateStatement(
	anchorID string,
	subjectID string,
	subjectPub *ecdsa.PublicKey,
	subjectKID string,
	anchorSigningKey *ecdsa.PrivateKey,
	anchorKID string,
	ttl time.Duration,
) (string, error) {
	leafJWK, err := keys.PublicKeyToJWK(subjectPub, subjectKID)
	if err != nil {
		return "", fmt.Errorf("serialize leaf JWK: %w", err)
	}
	jwkMap, err := toMap(leafJWK)
	if err != nil {
		return "", fmt.Errorf("convert leaf JWK to map: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": anchorID,
		"sub": subjectID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jwks": map[string]interface{}{
			"keys": []interface{}{jwkMap},
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = entityStatementTyp
	t.Header["kid"] = anchorKID
	return t.SignedString(anchorSigningKey)
}

// ParseEntityConfiguration decodes without verifying the signature.
func ParseEntityConfiguration(tokenStr string) (*EntityConfiguration, error) {
	payload, err := peekPayload(tokenStr)
	if err != nil {
		return nil, err
	}
	var ec EntityConfiguration
	if err := json.Unmarshal(payload, &ec); err != nil {
		return nil, fmt.Errorf("unmarshal entity configuration: %w", err)
	}
	if ec.Issuer == "" || ec.Subject == "" {
		return nil, errors.New("entity configuration missing iss or sub")
	}
	return &ec, nil
}

// ParseSubordinateStatement decodes without verifying the signature.
func ParseSubordinateStatement(tokenStr string) (*SubordinateStatement, error) {
	payload, err := peekPayload(tokenStr)
	if err != nil {
		return nil, err
	}
	var ss SubordinateStatement
	if err := json.Unmarshal(payload, &ss); err != nil {
		return nil, fmt.Errorf("unmarshal subordinate statement: %w", err)
	}
	if ss.Issuer == "" || ss.Subject == "" {
		return nil, errors.New("subordinate statement missing iss or sub")
	}
	return &ss, nil
}

// VerifyEntityConfiguration verifies the ES256 signature and returns the typed payload.
func VerifyEntityConfiguration(tokenStr string, pub *ecdsa.PublicKey) (*EntityConfiguration, error) {
	claims, err := verifyEntityStatement(tokenStr, pub)
	if err != nil {
		return nil, fmt.Errorf("verify entity configuration: %w", err)
	}
	b, _ := json.Marshal(map[string]interface{}(claims))
	var ec EntityConfiguration
	if err := json.Unmarshal(b, &ec); err != nil {
		return nil, fmt.Errorf("unmarshal verified entity configuration: %w", err)
	}
	return &ec, nil
}

// VerifySubordinateStatement verifies a Subordinate Statement JWT using the Trust
// Anchor's public key.
func VerifySubordinateStatement(tokenStr string, anchorPub *ecdsa.PublicKey) (*SubordinateStatement, error) {
	claims, err := verifyEntityStatement(tokenStr, anchorPub)
	if err != nil {
		return nil, fmt.Errorf("verify subordinate statement: %w", err)
	}
	b, _ := json.Marshal(map[string]interface{}(claims))
	var ss SubordinateStatement
	if err := json.Unmarshal(b, &ss); err != nil {
		return nil, fmt.Errorf("unmarshal verified subordinate statement: %w", err)
	}
	return &ss, nil
}

// ---------- internal helpers ----------

func verifyEntityStatement(tokenStr string, pub *ecdsa.PublicKey) (jwt.MapClaims, error) {
	p := jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"ES256"}))
	var claims jwt.MapClaims
	t, err := p.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		typ, _ := t.Header["typ"].(string)
		if typ != entityStatementTyp {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, entityStatementTyp)
		}
		return pub, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid entity statement")
	}
	return claims, nil
}

func peekPayload(tokenStr string) ([]byte, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	return b, nil
}

func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	return m, json.Unmarshal(b, &m)
}
