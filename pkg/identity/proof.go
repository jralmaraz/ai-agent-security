package identity

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const agentProofType = "application/agent-proof+jwt"

// defaultProofTTL is the default expiry for an AgentProofToken.
const defaultProofTTL = 5 * time.Minute

// AgentProofClaims is the JWT payload for an AgentProofToken (per-request proof).
//
// The proof binds:
//   - aud: the target URI the request is headed to
//   - chain_hash: base64url(SHA-256(full delegation chain wire string))
//   - tth: optional base64url(SHA-256(Txn-Token)) — binds proof to a Transaction Token
//   - jti: unique ID to enable replay detection
type AgentProofClaims struct {
	jwt.RegisteredClaims
	ChainHash string `json:"chain_hash"`
	// Tth is the optional Transaction Token Hash (tth claim).
	// Set when the agent received a Txn-Token and wants to bind this proof
	// to that specific business transaction (draft-ietf-oauth-transaction-tokens).
	Tth string `json:"tth,omitempty"`
}

// ProofGenerateOptions controls AgentProofToken generation.
type ProofGenerateOptions struct {
	// TargetURI is the URL of the resource being accessed (becomes aud).
	TargetURI string
	// Chain is the delegation chain being proved.
	Chain AgentChain
	// WorkloadKey is the private key of the agent sending the proof.
	WorkloadKey *ecdsa.PrivateKey
	// TTL overrides the default 5-minute expiry. A zero value uses the default.
	// A negative value creates an already-expired token (for testing).
	TTL time.Duration
	// TxnToken is an optional compact Transaction Token JWT (draft-ietf-oauth-transaction-tokens).
	// When set, its SHA-256 hash is placed in the tth claim, binding this proof
	// to the business transaction that initiated the call chain.
	TxnToken string
}

// GenerateProof creates a signed AgentProofToken.
func GenerateProof(opts ProofGenerateOptions) (string, error) {
	if opts.TargetURI == "" {
		return "", errors.New("TargetURI is required")
	}
	if opts.Chain.Len() == 0 {
		return "", errors.New("Chain must not be empty")
	}
	if opts.WorkloadKey == nil {
		return "", errors.New("WorkloadKey is required")
	}

	ttl := opts.TTL
	if ttl == 0 {
		ttl = defaultProofTTL
	}

	var tth string
	if opts.TxnToken != "" {
		tth = hashToken(opts.TxnToken)
	}

	now := time.Now()
	claims := AgentProofClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{opts.TargetURI},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        generateJTI(),
		},
		ChainHash: opts.Chain.Hash(),
		Tth:       tth,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = agentProofType
	return t.SignedString(opts.WorkloadKey)
}

// ProofValidator validates AgentProofTokens and optionally detects replays
// via a pluggable JTIStore.
//
// The default store (InMemoryJTIStore) is suitable for single-process
// deployments. Swap it for a distributed store (etcd, Redis, CockroachDB)
// to share replay state across replicas — the plug-in point for
// multi-cloud / multi-replica deployments.
type ProofValidator struct {
	store  JTIStore
	parser *jwt.Parser
}

// NewProofValidator creates a validator backed by an InMemoryJTIStore.
func NewProofValidator() *ProofValidator {
	return &ProofValidator{
		store:  NewInMemoryJTIStore(),
		parser: jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithIssuedAt()),
	}
}

// NewProofValidatorWithStore creates a validator backed by the provided JTIStore.
// Use this to inject a distributed store in multi-replica deployments.
func NewProofValidatorWithStore(s JTIStore) *ProofValidator {
	return &ProofValidator{
		store:  s,
		parser: jwt.NewParser(jwt.WithExpirationRequired(), jwt.WithIssuedAt()),
	}
}

// ProofValidateOptions controls proof validation.
type ProofValidateOptions struct {
	// ProofToken is the compact AgentProofToken JWT.
	ProofToken string
	// Chain is the delegation chain that was presented alongside the proof.
	Chain AgentChain
	// RequestURI is the URI of the incoming request (must match aud).
	RequestURI string
	// WorkloadKey is the public key of the agent that signed the proof.
	WorkloadKey *ecdsa.PublicKey
	// CheckReplay enables jti-based replay detection (stateful).
	CheckReplay bool
	// TxnToken is the optional compact Transaction Token JWT that should be
	// bound to this proof via tth. When set, the validator verifies that
	// claims.Tth == SHA-256(TxnToken). Ignored when empty.
	TxnToken string
}

// Validate verifies the AgentProofToken.
//
// Checks performed:
//   - Signature (ES256, with provided WorkloadKey)
//   - typ header == "application/agent-proof+jwt"
//   - exp / nbf / iat
//   - aud == RequestURI
//   - chain_hash == SHA-256(chain.String())
//   - jti uniqueness (when CheckReplay is true)
func (v *ProofValidator) Validate(opts ProofValidateOptions) (*AgentProofClaims, error) {
	if opts.ProofToken == "" {
		return nil, errors.New("proof token is required")
	}
	if opts.WorkloadKey == nil {
		return nil, errors.New("workload key is required")
	}

	parsed, err := v.parser.ParseWithClaims(
		opts.ProofToken,
		&AgentProofClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if typ, _ := t.Header["typ"].(string); typ != agentProofType {
				return nil, fmt.Errorf("unexpected typ %q, want %q", typ, agentProofType)
			}
			return opts.WorkloadKey, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("parse proof: %w", err)
	}
	claims, ok := parsed.Claims.(*AgentProofClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("invalid proof claims")
	}

	// Validate audience manually.
	audOK := false
	for _, a := range claims.Audience {
		if a == opts.RequestURI {
			audOK = true
			break
		}
	}
	if !audOK {
		return nil, fmt.Errorf("aud mismatch: %q not in %v", opts.RequestURI, []string(claims.Audience))
	}

	// Verify chain binding.
	wantHash := opts.Chain.Hash()
	if claims.ChainHash != wantHash {
		return nil, fmt.Errorf("chain_hash mismatch: want %s got %s", wantHash, claims.ChainHash)
	}

	// Verify tth binds this proof to the presented Transaction Token (if supplied).
	if opts.TxnToken != "" {
		expectedTth := hashToken(opts.TxnToken)
		if claims.Tth != expectedTth {
			return nil, errors.New("proof tth does not match Transaction Token hash")
		}
	}

	// Replay detection: delegate to the JTIStore.
	if opts.CheckReplay {
		jti := claims.ID
		if jti == "" {
			return nil, errors.New("proof token missing jti")
		}
		if err := v.store.Record(jti, claims.ExpiresAt.Time); err != nil {
			return nil, fmt.Errorf("proof replay check: %w", err)
		}
	}

	return claims, nil
}
