package cb4a

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const pdpDecisionType = "pdp-decision+jwt"

// ApprovalTier defines the required approval level for a credential request.
type ApprovalTier int

const (
	// TierAuto is automatic approval for low-risk operations (e.g. read-only).
	TierAuto ApprovalTier = 1
	// TierHITL requires human-in-the-loop async approval (e.g. financial writes).
	TierHITL ApprovalTier = 2
	// TierMFA requires synchronous FIDO2/MFA verification (e.g. production admin ops).
	TierMFA ApprovalTier = 3
)

// PolicyRule maps an (agent, scope) pattern pair to an approval tier.
// Patterns support shell-style globs via path.Match semantics.
type PolicyRule struct {
	// AgentPattern is matched against the requesting agent's SVID.
	AgentPattern string
	// ScopePattern is matched against the requested OAuth2 scope.
	ScopePattern string
	// Tier is the required approval level when this rule matches.
	Tier ApprovalTier
}

// matchPattern returns true if value matches the shell glob pattern.
// "*" matches everything. Otherwise path.Match semantics apply.
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	matched, _ := path.Match(pattern, value)
	return matched
}

// DefaultPolicyRules returns a representative rule set for the demo.
// Rules are evaluated top-to-bottom; first match wins.
func DefaultPolicyRules() []PolicyRule {
	return []PolicyRule{
		// Admin identities always require MFA.
		{AgentPattern: "spiffe://*/admin/*", ScopePattern: "*", Tier: TierMFA},
		// CI/CD pipeline agents require HITL for safety.
		{AgentPattern: "spiffe://*/ci/*", ScopePattern: "*", Tier: TierHITL},
		// Financial write operations require human approval.
		{AgentPattern: "*", ScopePattern: "billing:*:write", Tier: TierHITL},
		{AgentPattern: "*", ScopePattern: "stripe:*:write", Tier: TierHITL},
		// Read-only scopes are auto-approved.
		{AgentPattern: "*", ScopePattern: "*:read", Tier: TierAuto},
		{AgentPattern: "*", ScopePattern: "*:*:read", Tier: TierAuto},
		// Default: require human approval for anything unmatched.
		{AgentPattern: "*", ScopePattern: "*", Tier: TierHITL},
	}
}

// PDPDecisionClaims is the payload of a signed PDP Decision JWT.
type PDPDecisionClaims struct {
	jwt.RegisteredClaims

	AgentSVID  string       `json:"agent_svid"`
	Target     string       `json:"target"`
	Action     string       `json:"action"`
	Scope      string       `json:"scope"`
	Tier       ApprovalTier `json:"tier"`
	Approved   bool         `json:"approved"`
	RequestID  string       `json:"request_id"`
	ApproverID string       `json:"approver_id,omitempty"`
}

// RequestState tracks a pending request's lifecycle.
type RequestState string

const (
	StatePending  RequestState = "pending"
	StateApproved RequestState = "approved"
	StateDenied   RequestState = "denied"
)

// PendingRequest holds a HITL or MFA request awaiting human action.
type PendingRequest struct {
	ID        string
	EnvClaims *EnvelopeClaims
	Tier      ApprovalTier
	State     RequestState
	CreatedAt time.Time
}

// InMemoryPDP is a Policy Decision Point that evaluates Task Request Envelopes
// against a rule set and issues signed PDP Decision JWTs.
//
// The PDP has ZERO credential access — it only evaluates policy and issues
// decisions. Credentials live exclusively in the CDP's vault.
type InMemoryPDP struct {
	rules    []PolicyRule
	sigKey   *ecdsa.PrivateKey
	issuerID string
	ttl      time.Duration
	audit    *AuditLog

	mu      sync.RWMutex
	pending map[string]*PendingRequest
}

// NewInMemoryPDP creates a PDP.
func NewInMemoryPDP(issuerID string, sigKey *ecdsa.PrivateKey, rules []PolicyRule, ttl time.Duration, audit *AuditLog) *InMemoryPDP {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &InMemoryPDP{
		rules:    rules,
		sigKey:   sigKey,
		issuerID: issuerID,
		ttl:      ttl,
		audit:    audit,
		pending:  make(map[string]*PendingRequest),
	}
}

// evaluateTier returns the first matching tier for the given agent+scope pair.
func (p *InMemoryPDP) evaluateTier(agentSVID, scope string) ApprovalTier {
	for _, rule := range p.rules {
		if matchPattern(rule.AgentPattern, agentSVID) && matchPattern(rule.ScopePattern, scope) {
			return rule.Tier
		}
	}
	return TierHITL
}

// Evaluate processes a Task Request Envelope and returns:
//   - (decisionJWT, "", nil) for TierAuto requests (auto-approved immediately).
//   - ("", requestID, nil) for TierHITL/TierMFA requests awaiting human action.
func (p *InMemoryPDP) Evaluate(envClaims *EnvelopeClaims) (decisionJWT, requestID string, err error) {
	if envClaims == nil {
		return "", "", errors.New("envClaims is required")
	}

	reqID := generateID()
	tier := p.evaluateTier(envClaims.AgentSVID, envClaims.Scope)

	_ = p.audit.Append(AuditEntry{
		Event:     EventPolicyEvaluated,
		AgentSVID: envClaims.AgentSVID,
		Target:    envClaims.Target,
		Action:    envClaims.Action,
		Scope:     envClaims.Scope,
		Tier:      int(tier),
		RequestID: reqID,
		Detail:    fmt.Sprintf("tier=%d", tier),
		Success:   true,
	})

	if tier == TierAuto {
		j, issueErr := p.issueDecision(envClaims, tier, true, reqID, "auto")
		if issueErr != nil {
			return "", "", fmt.Errorf("issue auto decision: %w", issueErr)
		}
		_ = p.audit.Append(AuditEntry{
			Event:     EventApproved,
			AgentSVID: envClaims.AgentSVID,
			Target:    envClaims.Target,
			Action:    envClaims.Action,
			Scope:     envClaims.Scope,
			Tier:      int(tier),
			RequestID: reqID,
			Detail:    "auto-approved by policy",
			Success:   true,
		})
		return j, "", nil
	}

	// Park the request for human action.
	p.mu.Lock()
	p.pending[reqID] = &PendingRequest{
		ID:        reqID,
		EnvClaims: envClaims,
		Tier:      tier,
		State:     StatePending,
		CreatedAt: time.Now(),
	}
	p.mu.Unlock()

	return "", reqID, nil
}

// Approve resolves a pending request as approved and returns a signed decision JWT.
// approverID identifies the human approver for the audit trail.
func (p *InMemoryPDP) Approve(requestID, approverID string) (string, error) {
	p.mu.Lock()
	req, ok := p.pending[requestID]
	if !ok {
		p.mu.Unlock()
		return "", fmt.Errorf("unknown request: %s", requestID)
	}
	if req.State != StatePending {
		p.mu.Unlock()
		return "", fmt.Errorf("request %s is already %s", requestID, req.State)
	}
	req.State = StateApproved
	p.mu.Unlock()

	j, err := p.issueDecision(req.EnvClaims, req.Tier, true, requestID, approverID)
	if err != nil {
		return "", fmt.Errorf("issue decision: %w", err)
	}

	_ = p.audit.Append(AuditEntry{
		Event:     EventApproved,
		AgentSVID: req.EnvClaims.AgentSVID,
		Target:    req.EnvClaims.Target,
		Action:    req.EnvClaims.Action,
		Scope:     req.EnvClaims.Scope,
		Tier:      int(req.Tier),
		RequestID: requestID,
		Detail:    fmt.Sprintf("approved by %s", approverID),
		Success:   true,
	})

	return j, nil
}

// Deny resolves a pending request as denied.
func (p *InMemoryPDP) Deny(requestID, approverID string) error {
	p.mu.Lock()
	req, ok := p.pending[requestID]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("unknown request: %s", requestID)
	}
	if req.State != StatePending {
		p.mu.Unlock()
		return fmt.Errorf("request %s is already %s", requestID, req.State)
	}
	req.State = StateDenied
	p.mu.Unlock()

	_ = p.audit.Append(AuditEntry{
		Event:     EventDenied,
		AgentSVID: req.EnvClaims.AgentSVID,
		Target:    req.EnvClaims.Target,
		Action:    req.EnvClaims.Action,
		Scope:     req.EnvClaims.Scope,
		Tier:      int(req.Tier),
		RequestID: requestID,
		Detail:    fmt.Sprintf("denied by %s", approverID),
		Success:   false,
	})

	return nil
}

// Get returns a copy of the pending request with the given ID, or nil.
func (p *InMemoryPDP) Get(requestID string) *PendingRequest {
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.pending[requestID]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

// ListPending returns all requests in the pending state.
func (p *InMemoryPDP) ListPending() []*PendingRequest {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var out []*PendingRequest
	for _, r := range p.pending {
		if r.State == StatePending {
			cp := *r
			out = append(out, &cp)
		}
	}
	return out
}

func (p *InMemoryPDP) issueDecision(env *EnvelopeClaims, tier ApprovalTier, approved bool, requestID, approverID string) (string, error) {
	now := time.Now()
	claims := PDPDecisionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuerID,
			Subject:   env.AgentSVID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.ttl)),
			ID:        generateID(),
		},
		AgentSVID:  env.AgentSVID,
		Target:     env.Target,
		Action:     env.Action,
		Scope:      env.Scope,
		Tier:       tier,
		Approved:   approved,
		RequestID:  requestID,
		ApproverID: approverID,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = pdpDecisionType
	return t.SignedString(p.sigKey)
}

// ParseDecision verifies a PDP Decision JWT using the PDP's public key.
func ParseDecision(decisionJWT string, pdpPub *ecdsa.PublicKey) (*PDPDecisionClaims, error) {
	if pdpPub == nil {
		return nil, errors.New("pdpPub is required")
	}
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)
	parsed, err := parser.ParseWithClaims(decisionJWT, &PDPDecisionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != pdpDecisionType {
			return nil, fmt.Errorf("unexpected typ %q, want %q", typ, pdpDecisionType)
		}
		return pdpPub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse decision: %w", err)
	}
	claims, ok := parsed.Claims.(*PDPDecisionClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid decision claims")
	}
	return claims, nil
}
