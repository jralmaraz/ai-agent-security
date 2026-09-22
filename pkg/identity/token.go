// Package identity provides agent token issuance and validation for the
// WIMSE agent-fabric identity layer.
//
// AgentToken (typ: agent+jwt) is a WIT-superset per AIMS §7:
// "Each AI agent component MUST possess a Workload Identity Token (WIT) ...
// that provides cryptographic binding to their agent identifier."
//
// The AgentToken carries all WIMSE-CRED claims (sub as SPIFFE URI, cnf.jwk
// key binding, iss/exp/nbf/iat/jti) via the embedded wit.Claims, with
// agent-specific extensions (role, chain_depth, agent_mission) layered on top.
// The typ header is "agent+jwt" rather than "wit+jwt" to distinguish the
// extended profile at the application layer.
package identity

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jralmaraz/wimse-identity-fabric/pkg/wit"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/ai-agent-security/pkg/keys"
)

const agentTokenType = "agent+jwt"

// Role constants for AgentClaims.Role.
const (
	RoleOrchestrator = "orchestrator"
	RoleExecutor     = "executor"
	RoleToolServer   = "tool-server"
)

// AgentClaims is the JWT payload for an AgentToken.
//
// Embedding wit.Claims gives every AgentToken the full WIMSE-CRED claim set:
//   - RegisteredClaims (iss, sub, aud, exp, nbf, iat, jti)
//   - sub MUST be a SPIFFE URI identifying the agent workload
//   - Cnf.JWK binds the token to the agent's public key (RFC 7800 §3.2)
//   - TrustDomain (optional) carries the SPIFFE trust domain
//
// The agent-specific extensions (Role, ChainDepth, Mission) are layered
// on top of this WIT base.
type AgentClaims struct {
	wit.Claims

	// Role is the operational role of this agent workload.
	Role string `json:"role"`

	// ChainDepth is the 0-indexed hop position in a delegation chain.
	// The originating orchestrator has depth 0.
	ChainDepth int `json:"chain_depth"`

	// Mission is an optional human-readable description of the approved
	// scope of action for this agent — e.g. "Summarise Q2 financial reports".
	// Defined in draft-klrc-aiagent-auth §4 (Agent Mission claim).
	Mission string `json:"agent_mission,omitempty"`
}

// ValidatedAgent is returned by AgentValidator.Validate on success.
type ValidatedAgent struct {
	Claims      *AgentClaims
	WorkloadKey *ecdsa.PublicKey
}

// IssueOptions controls what goes into an AgentToken.
type IssueOptions struct {
	Subject     string            // SPIFFE URI (AIMS §7 MUST be set)
	Audiences   []string          // intended recipients
	TrustDomain string            // SPIFFE trust domain (optional)
	Role        string            // RoleOrchestrator | RoleExecutor | RoleToolServer
	ChainDepth  int               // 0 for originating orchestrator
	KeyID       string            // kid header (optional)
	WorkloadKey *ecdsa.PublicKey  // agent's own public key → cnf.jwk
	Mission     string            // optional: approved scope of action (agent_mission claim)
}

// AgentIssuer issues AgentTokens signed with an IdP EC P-256 key.
type AgentIssuer struct {
	issuerID string
	sigKey   *ecdsa.PrivateKey
	ttl      time.Duration
}

// NewAgentIssuer creates an issuer.
// issuerID must be an absolute URI (e.g. "https://idp.cloud-a.example").
func NewAgentIssuer(issuerID string, sigKey *ecdsa.PrivateKey, ttl time.Duration) *AgentIssuer {
	return &AgentIssuer{issuerID: issuerID, sigKey: sigKey, ttl: ttl}
}

// Issue mints a signed AgentToken.
func (i *AgentIssuer) Issue(opts IssueOptions) (string, error) {
	if opts.Subject == "" {
		return "", errors.New("subject is required")
	}
	if opts.Role == "" {
		return "", errors.New("role is required")
	}
	if opts.WorkloadKey == nil {
		return "", errors.New("workload key is required")
	}

	jwk, err := keys.PublicKeyToJWK(opts.WorkloadKey, opts.KeyID)
	if err != nil {
		return "", fmt.Errorf("serialize workload key: %w", err)
	}
	jwkRaw, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK: %w", err)
	}

	now := time.Now()
	claims := AgentClaims{
		Claims: wit.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    i.issuerID,
				Subject:   opts.Subject,
				Audience:  jwt.ClaimStrings(opts.Audiences),
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
				ID:        generateJTI(),
			},
			TrustDomain: opts.TrustDomain,
			Cnf:         wit.ConfirmationKey{JWK: json.RawMessage(jwkRaw)},
		},
		Role:       opts.Role,
		ChainDepth: opts.ChainDepth,
		Mission:    opts.Mission,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	if opts.KeyID != "" {
		t.Header["kid"] = opts.KeyID
	}
	t.Header["typ"] = agentTokenType

	return t.SignedString(i.sigKey)
}

// AgentValidator validates AgentTokens issued by a known IdP.
type AgentValidator struct {
	issuerID string
	idpPub   *ecdsa.PublicKey
	parser   *jwt.Parser
}

// NewAgentValidator creates a validator.
// idpPub is the IdP's EC P-256 public key used to verify token signatures.
func NewAgentValidator(issuerID string, idpPub *ecdsa.PublicKey, opts ...jwt.ParserOption) *AgentValidator {
	defaults := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	}
	return &AgentValidator{
		issuerID: issuerID,
		idpPub:   idpPub,
		parser:   jwt.NewParser(append(defaults, opts...)...),
	}
}

// Validate verifies the token's signature, expiry, issuer, and typ header,
// then extracts the agent's public key from cnf.jwk.
func (v *AgentValidator) Validate(token string) (*ValidatedAgent, error) {
	parsed, err := v.parser.ParseWithClaims(token, &AgentClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != agentTokenType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, agentTokenType)
		}
		return v.idpPub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse agent token: %w", err)
	}
	claims, ok := parsed.Claims.(*AgentClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid agent token claims")
	}
	if claims.Issuer != v.issuerID {
		return nil, fmt.Errorf("issuer mismatch: want %q got %q", v.issuerID, claims.Issuer)
	}

	if len(claims.Cnf.JWK) == 0 {
		return nil, errors.New("agent token missing cnf.jwk claim")
	}
	var jwk keys.JWK
	if err := json.Unmarshal(claims.Cnf.JWK, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshal cnf.jwk: %w", err)
	}
	workloadKey, err := keys.JWKToPublicKey(&jwk)
	if err != nil {
		return nil, fmt.Errorf("deserialize workload key: %w", err)
	}

	return &ValidatedAgent{Claims: claims, WorkloadKey: workloadKey}, nil
}
