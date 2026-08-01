package cb4a

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

const (
	cb4aTokenType = "cb4a-token+jwt"
	dpopProofType = "dpop+jwt"
)

// InMemoryVault simulates an HSM-backed credential store.
// Only the CDP has access; the PDP and agents never touch it directly.
// In production this would be HashiCorp Vault, AWS Secrets Manager, or an HSM.
type InMemoryVault struct {
	mu    sync.RWMutex
	creds map[string]string // scope → base credential (API key / OAuth client secret)
}

// NewInMemoryVault creates a vault pre-seeded with demo credentials.
func NewInMemoryVault() *InMemoryVault {
	return &InMemoryVault{
		creds: map[string]string{
			"billing:invoices:read":  "sk-billing-read-xQf2mP9",
			"billing:invoices:write": "sk-billing-write-rT7nZ3k",
			"analytics:events:read":  "sk-analytics-Kj4vLm8",
			"github:repos:read":      "ghp_demo_N2bXpQ5",
			"stripe:charges:write":   "sk_live_demo_Wc6yRs1",
		},
	}
}

func (v *InMemoryVault) get(scope string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	c, ok := v.creds[scope]
	return c, ok
}

// CB4ATokenClaims is the payload of a short-lived, DPoP-bound access token.
// The cnf.jkt claim binds the token to the agent's ephemeral DPoP key.
type CB4ATokenClaims struct {
	jwt.RegisteredClaims

	AgentSVID string `json:"agent_svid"`
	Target    string `json:"target"`
	Action    string `json:"action"`
	Scope     string `json:"scope"`
	RequestID string `json:"request_id"`
	Cnf       struct {
		// JKT is the RFC 7638 JWK Thumbprint of the ephemeral DPoP key.
		JKT string `json:"jkt"`
	} `json:"cnf"`
}

// MintedCredential is returned by CDP.Mint.
type MintedCredential struct {
	// Token is the signed CB4A access token (cb4a-token+jwt).
	Token string
	// EphemeralKey is the private key for generating DPoP proofs.
	// The agent holds this key; it is never persisted.
	EphemeralKey *ecdsa.PrivateKey
	// EphemeralPub is the public portion embedded in the token's cnf.jkt.
	EphemeralPub *ecdsa.PublicKey
	// Scope is the scope this credential is valid for.
	Scope string
	// ExpiresAt is when the CB4A token expires.
	ExpiresAt time.Time
}

// DPoPProofClaims is the payload of a per-request DPoP proof JWT (RFC 9449).
type DPoPProofClaims struct {
	jwt.RegisteredClaims

	// HTTPMethod is the HTTP method of the target request.
	HTTPMethod string `json:"htm"`
	// HTTPURI is the target URI of the request.
	HTTPURI string `json:"htu"`
	// ATH is base64url(SHA-256(access_token)), binding the proof to a specific token.
	ATH string `json:"ath"`
}

// CDP is the Credential Delivery Point.
//
// It verifies signed PDP decisions and mints short-lived, DPoP-bound access
// tokens. The CDP has ZERO policy authority — it only acts on decisions it
// can cryptographically verify were issued by a trusted PDP.
type CDP struct {
	vault    *InMemoryVault
	pdpPub   *ecdsa.PublicKey
	sigKey   *ecdsa.PrivateKey
	issuerID string
	tokenTTL time.Duration
	audit    *AuditLog

	mu      sync.Mutex
	dpopJTI map[string]time.Time // jti → expiry (replay store for DPoP proofs)
}

// NewCDP creates a CDP.
func NewCDP(vault *InMemoryVault, pdpPub *ecdsa.PublicKey, sigKey *ecdsa.PrivateKey, issuerID string, tokenTTL time.Duration, audit *AuditLog) *CDP {
	if tokenTTL <= 0 {
		tokenTTL = 15 * time.Minute
	}
	return &CDP{
		vault:    vault,
		pdpPub:   pdpPub,
		sigKey:   sigKey,
		issuerID: issuerID,
		tokenTTL: tokenTTL,
		audit:    audit,
		dpopJTI:  make(map[string]time.Time),
	}
}

// Mint verifies the PDP decision and returns a DPoP-bound access token.
//
// A fresh ephemeral EC P-256 key pair is generated for every call; the
// private half is returned in MintedCredential for DPoP proof generation.
// The base credential in the vault is never returned to the agent — only
// the short-lived, sender-constrained token is.
func (c *CDP) Mint(decisionJWT string) (*MintedCredential, error) {
	decision, err := ParseDecision(decisionJWT, c.pdpPub)
	if err != nil {
		return nil, fmt.Errorf("invalid PDP decision: %w", err)
	}
	if !decision.Approved {
		return nil, errors.New("PDP decision is not approved")
	}

	// Confirm the vault holds a credential for this scope (fail-fast).
	if _, ok := c.vault.get(decision.Scope); !ok {
		return nil, fmt.Errorf("no credential in vault for scope %q", decision.Scope)
	}

	// Generate a fresh ephemeral key pair for this mint.
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral DPoP key: %w", err)
	}

	// Compute the JWK Thumbprint (RFC 7638) for the cnf.jkt claim.
	jkt, err := jwkThumbprint(kp.Public)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	now := time.Now()
	exp := now.Add(c.tokenTTL)
	claims := CB4ATokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    c.issuerID,
			Subject:   decision.AgentSVID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        generateID(),
		},
		AgentSVID: decision.AgentSVID,
		Target:    decision.Target,
		Action:    decision.Action,
		Scope:     decision.Scope,
		RequestID: decision.RequestID,
	}
	claims.Cnf.JKT = jkt

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = cb4aTokenType
	tokenStr, err := tok.SignedString(c.sigKey)
	if err != nil {
		return nil, fmt.Errorf("sign CB4A token: %w", err)
	}

	// Fail-closed: audit must succeed before returning the token.
	if auditErr := c.audit.Append(AuditEntry{
		Event:     EventCredentialMinted,
		AgentSVID: decision.AgentSVID,
		Target:    decision.Target,
		Action:    decision.Action,
		Scope:     decision.Scope,
		Tier:      int(decision.Tier),
		RequestID: decision.RequestID,
		Detail:    fmt.Sprintf("jkt=%s ttl=%s", jkt, c.tokenTTL),
		Success:   true,
	}); auditErr != nil {
		return nil, fmt.Errorf("audit write failed (fail-closed): %w", auditErr)
	}

	return &MintedCredential{
		Token:        tokenStr,
		EphemeralKey: kp.Private,
		EphemeralPub: kp.Public,
		Scope:        decision.Scope,
		ExpiresAt:    exp,
	}, nil
}

// GenerateDPoPProof creates a per-request DPoP proof JWT (RFC 9449).
//
// The proof JWT embeds the ephemeral public key in its header (jwk field)
// so the resource server can verify both the signature and the key binding.
func GenerateDPoPProof(mc *MintedCredential, method, uri string) (string, error) {
	if mc == nil {
		return "", errors.New("MintedCredential is required")
	}
	if method == "" || uri == "" {
		return "", errors.New("method and uri are required")
	}

	// ath = base64url(SHA-256(access_token)) — binds proof to specific token.
	h := sha256.Sum256([]byte(mc.Token))
	ath := encodeBase64url(h[:])

	now := time.Now()
	claims := DPoPProofClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
			ID:        generateID(),
		},
		HTTPMethod: method,
		HTTPURI:    uri,
		ATH:        ath,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = dpopProofType

	// RFC 9449 §4.2: embed the public JWK in the proof header.
	jwk, err := keys.PublicKeyToJWK(mc.EphemeralPub, "")
	if err != nil {
		return "", fmt.Errorf("serialize ephemeral public key: %w", err)
	}
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", fmt.Errorf("marshal JWK for DPoP header: %w", err)
	}
	tok.Header["jwk"] = json.RawMessage(jwkBytes)

	return tok.SignedString(mc.EphemeralKey)
}

// SimulateAPICall mimics what a resource server does when it receives a request
// with Authorization: DPoP <cb4a-token> and DPoP: <dpop-proof> headers.
//
// Verifications performed:
//  1. CB4A token signature + expiry (using CDP signing key as issuer)
//  2. DPoP proof signature (using the public key embedded in the proof header)
//  3. DPoP proof typ header
//  4. htm (method) and htu (URI) match the actual request
//  5. ath = base64url(SHA-256(token)) — proof is bound to this specific token
//  6. cnf.jkt in token matches the JWK Thumbprint of the proof's embedded key
//  7. DPoP jti replay detection (per-proof deduplication)
func (c *CDP) SimulateAPICall(tokenStr, dpopProof, method, uri string) error {
	// Step 1: verify the CB4A token.
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	)
	parsedTok, err := parser.ParseWithClaims(tokenStr, &CB4ATokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != cb4aTokenType {
			return nil, fmt.Errorf("unexpected CB4A token typ %q", typ)
		}
		return &c.sigKey.PublicKey, nil
	})
	if err != nil {
		return fmt.Errorf("invalid CB4A token: %w", err)
	}
	tokClaims := parsedTok.Claims.(*CB4ATokenClaims)

	// Steps 2–3: parse the DPoP proof and extract the embedded public key.
	var proofPub *ecdsa.PublicKey
	parsedProof, err := parser.ParseWithClaims(dpopProof, &DPoPProofClaims{}, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); typ != dpopProofType {
			return nil, fmt.Errorf("unexpected DPoP proof typ %q", typ)
		}
		// Extract the public JWK embedded in the header per RFC 9449 §4.2.
		// jwt/v5 deserializes headers into map[string]interface{}, so we
		// re-marshal and unmarshal into our JWK struct.
		jwkRaw, marshalErr := json.Marshal(t.Header["jwk"])
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal DPoP proof jwk: %w", marshalErr)
		}
		var jwkVal keys.JWK
		if unmarshalErr := json.Unmarshal(jwkRaw, &jwkVal); unmarshalErr != nil {
			return nil, fmt.Errorf("parse DPoP proof jwk: %w", unmarshalErr)
		}
		pub, convErr := keys.JWKToPublicKey(&jwkVal)
		if convErr != nil {
			return nil, convErr
		}
		proofPub = pub
		return pub, nil
	})
	if err != nil {
		return fmt.Errorf("verify DPoP proof: %w", err)
	}
	proofClaims := parsedProof.Claims.(*DPoPProofClaims)

	// Step 4: verify htm and htu.
	if proofClaims.HTTPMethod != method {
		return fmt.Errorf("DPoP htm mismatch: want %q got %q", method, proofClaims.HTTPMethod)
	}
	if proofClaims.HTTPURI != uri {
		return fmt.Errorf("DPoP htu mismatch: want %q got %q", uri, proofClaims.HTTPURI)
	}

	// Step 5: verify ath.
	h := sha256.Sum256([]byte(tokenStr))
	wantATH := encodeBase64url(h[:])
	if proofClaims.ATH != wantATH {
		return errors.New("DPoP ath mismatch: proof is not bound to the presented token")
	}

	// Step 6: verify cnf.jkt key binding.
	if proofPub == nil {
		return errors.New("DPoP proof public key not extracted")
	}
	wantJKT, err := jwkThumbprint(proofPub)
	if err != nil {
		return fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	if tokClaims.Cnf.JKT != wantJKT {
		return fmt.Errorf("DPoP key binding mismatch: token jkt %q ≠ proof key jkt %q",
			tokClaims.Cnf.JKT, wantJKT)
	}

	// Step 7: DPoP jti replay detection.
	jti := proofClaims.ID
	if jti == "" {
		return errors.New("DPoP proof missing jti")
	}
	c.mu.Lock()
	if _, seen := c.dpopJTI[jti]; seen {
		c.mu.Unlock()
		_ = c.audit.Append(AuditEntry{
			Event:     EventReplayRejected,
			AgentSVID: tokClaims.AgentSVID,
			Target:    uri,
			Action:    method,
			Scope:     tokClaims.Scope,
			RequestID: tokClaims.RequestID,
			Detail:    fmt.Sprintf("duplicate DPoP jti %s", jti),
			Success:   false,
		})
		return fmt.Errorf("DPoP proof replay detected: jti %s already seen", jti)
	}
	c.dpopJTI[jti] = proofClaims.ExpiresAt.Time
	c.mu.Unlock()

	_ = c.audit.Append(AuditEntry{
		Event:     EventAPICall,
		AgentSVID: tokClaims.AgentSVID,
		Target:    uri,
		Action:    method,
		Scope:     tokClaims.Scope,
		RequestID: tokClaims.RequestID,
		Detail:    "api call authorized",
		Success:   true,
	})

	return nil
}

// jwkThumbprint computes the RFC 7638 JWK Thumbprint for an EC P-256 public key.
// The canonical JSON member set in lexicographic order is: crv, kty, x, y.
func jwkThumbprint(pub *ecdsa.PublicKey) (string, error) {
	jwk, err := keys.PublicKeyToJWK(pub, "")
	if err != nil {
		return "", err
	}
	// RFC 7638 §3.3: lexicographic member order, no whitespace.
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
	h := sha256.Sum256([]byte(canonical))
	return encodeBase64url(h[:]), nil
}
