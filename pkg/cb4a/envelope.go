// Package cb4a implements the Credential Broker for Agents protocol
// (draft-hartman-credential-broker-4-agents-00).
//
// The protocol separates policy decisions (PDP) from credential delivery (CDP),
// ensuring that no single component ever holds both policy authority and
// credential access simultaneously.
//
// Flow:
//
//	Agent → [NewEnvelope] → Task Request Envelope JWT (tre+jwt)
//	Agent → PDP.Evaluate  → PDP Decision JWT  (pdp-decision+jwt)  [or pending ID]
//	Agent → CDP.Mint      → CB4A Token (cb4a-token+jwt) + ephemeral DPoP key
//	Agent → [GenerateDPoPProof] → DPoP Proof JWT (dpop+jwt)
//	Agent → Resource Server [Authorization: DPoP <token>, DPoP: <proof>]
//	Resource Server → CDP.SimulateAPICall → verified ✓
package cb4a

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const envelopeType = "tre+jwt"

// EnvelopeClaims is the payload of a Task Request Envelope JWT.
//
// The envelope is signed by the agent and submitted to the PDP.
// Note: Justification is a forensics-only field — it is intentionally
// excluded from authorization decisions so that creative wording cannot
// escalate privileges.
type EnvelopeClaims struct {
	jwt.RegisteredClaims

	// AgentSVID is the SPIFFE SVID of the requesting agent.
	AgentSVID string `json:"agent_svid"`
	// Target is the external API or resource endpoint being accessed.
	Target string `json:"target"`
	// Action is the HTTP method or operation (GET, POST, write, read, etc.).
	Action string `json:"action"`
	// Scope is the OAuth2-style scope required.
	Scope string `json:"scope"`
	// Justification is a human-readable reason for the request.
	// Forensics only — never used by the PDP for authorization.
	Justification string `json:"justification,omitempty"`
}

// NewEnvelope signs and returns a Task Request Envelope JWT.
func NewEnvelope(agentSVID, target, action, scope, justification string, ttl time.Duration, key *ecdsa.PrivateKey) (string, error) {
	if agentSVID == "" {
		return "", errors.New("agentSVID is required")
	}
	if target == "" {
		return "", errors.New("target is required")
	}
	if action == "" {
		return "", errors.New("action is required")
	}
	if scope == "" {
		return "", errors.New("scope is required")
	}
	if key == nil {
		return "", errors.New("signing key is required")
	}
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	now := time.Now()
	claims := EnvelopeClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   agentSVID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        generateID(),
		},
		AgentSVID:     agentSVID,
		Target:        target,
		Action:        action,
		Scope:         scope,
		Justification: justification,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = envelopeType
	return t.SignedString(key)
}

// ParseEnvelope verifies a Task Request Envelope JWT signed by the agent.
func ParseEnvelope(tokenStr string, agentPub *ecdsa.PublicKey) (*EnvelopeClaims, error) {
	if agentPub == nil {
		return nil, errors.New("agentPub is required")
	}
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)
	parsed, err := parser.ParseWithClaims(tokenStr, &EnvelopeClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != envelopeType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, envelopeType)
		}
		return agentPub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	claims, ok := parsed.Claims.(*EnvelopeClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid envelope claims")
	}
	return claims, nil
}
