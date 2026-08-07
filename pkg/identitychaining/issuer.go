package identitychaining

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/golang-jwt/jwt/v5"
)

const defaultGrantTTL = 5 * time.Minute

// GrantIssuer is the domain-A AS component that validates an agent's AgentToken
// and issues a JWT Authorization Grant targeting domain B's token endpoint.
type GrantIssuer struct {
	issuerID       string
	key            *ecdsa.PrivateKey
	agentValidator *identity.AgentValidator
	ttl            time.Duration
}

// NewGrantIssuer creates a GrantIssuer.
//
//   - issuerID: domain A's issuer URL (becomes iss in the grant)
//   - key: domain A's signing key (used to sign the grant)
//   - agentValidator: validates the incoming AgentToken before a grant is issued
//   - ttl: grant lifetime; zero or negative uses 5 minutes
func NewGrantIssuer(issuerID string, key *ecdsa.PrivateKey, agentValidator *identity.AgentValidator, ttl time.Duration) *GrantIssuer {
	if ttl == 0 {
		ttl = defaultGrantTTL
	}
	return &GrantIssuer{issuerID: issuerID, key: key, agentValidator: agentValidator, ttl: ttl}
}

// Issue validates subjectToken (an AgentToken) and issues a JWT Authorization Grant
// addressing targetAudience (domain B's token endpoint URL).
//
// The returned compact JWT carries:
//   - iss: domain A's issuer ID (this AS)
//   - sub: agent's SPIFFE ID extracted from the validated AgentToken
//   - aud: targetAudience (domain B's token endpoint)
//   - iat/exp: issuance and expiry timestamps
//   - jti: unique grant ID (prevents replay)
//   - typ: "jwt-authz-grant"
//   - act: optional RFC 8693 §4.1 actor claim; pass to distinguish the delegating
//     agent (sub) from the agent actually making the cross-domain call (act.sub).
func (g *GrantIssuer) Issue(subjectToken, targetAudience string, actor ...*ActorClaims) (string, error) {
	if subjectToken == "" {
		return "", errors.New("subject token is required")
	}
	if targetAudience == "" {
		return "", errors.New("target audience is required")
	}

	result, err := g.agentValidator.Validate(subjectToken)
	if err != nil {
		return "", fmt.Errorf("validate subject AgentToken: %w", err)
	}

	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	var act *ActorClaims
	if len(actor) > 0 {
		act = actor[0]
	}

	now := time.Now()
	claims := GrantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuerID,
			Subject:   result.Claims.Subject,
			Audience:  jwt.ClaimStrings{targetAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(g.ttl)),
			ID:        base64.RawURLEncoding.EncodeToString(jtiRaw),
		},
		Act: act,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = GrantTokenType
	return t.SignedString(g.key)
}
