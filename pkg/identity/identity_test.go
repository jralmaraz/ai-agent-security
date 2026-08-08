package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func mustKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, &priv.PublicKey
}

func newIssuerValidator(t *testing.T) (*identity.AgentIssuer, *identity.AgentValidator, *ecdsa.PrivateKey) {
	t.Helper()
	idpPriv, idpPub := mustKeyPair(t)
	issuer := identity.NewAgentIssuer("https://idp.example", idpPriv, time.Hour)
	validator := identity.NewAgentValidator("https://idp.example", idpPub)
	return issuer, validator, idpPriv
}

// ── AgentToken tests ──────────────────────────────────────────────────────────

func TestAgentToken_HappyPath(t *testing.T) {
	issuer, validator, _ := newIssuerValidator(t)
	_, wlPub := mustKeyPair(t)

	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://cloud-a.example/agent/orchestrator",
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: wlPub,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	va, err := validator.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if va.Claims.Role != identity.RoleOrchestrator {
		t.Errorf("role: want %q got %q", identity.RoleOrchestrator, va.Claims.Role)
	}
	if va.Claims.ChainDepth != 0 {
		t.Errorf("chain_depth: want 0 got %d", va.Claims.ChainDepth)
	}
	if va.WorkloadKey == nil {
		t.Error("workload key should not be nil")
	}
}

func TestAgentToken_TypHeader(t *testing.T) {
	issuer, _, _ := newIssuerValidator(t)
	_, wlPub := mustKeyPair(t)

	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://example/agent",
		Role:        identity.RoleExecutor,
		WorkloadKey: wlPub,
	})

	// Peek at header without verifying.
	parsed, _, err := new(jwt.Parser).ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if typ := parsed.Header["typ"]; typ != "agent+jwt" {
		t.Errorf("typ: want agent+jwt got %v", typ)
	}
}

func TestAgentToken_WrongKey(t *testing.T) {
	issuer, _, _ := newIssuerValidator(t)
	_, wlPub := mustKeyPair(t)

	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://example/agent",
		Role:        identity.RoleExecutor,
		WorkloadKey: wlPub,
	})

	// Validate with a different IdP key pair.
	_, wrongPub := mustKeyPair(t)
	wrongValidator := identity.NewAgentValidator("https://idp.example", wrongPub)
	if _, err := wrongValidator.Validate(tok); err == nil {
		t.Error("expected error for wrong validation key")
	}
}

func TestAgentToken_Expired(t *testing.T) {
	idpPriv, idpPub := mustKeyPair(t)
	issuer := identity.NewAgentIssuer("https://idp.example", idpPriv, -1*time.Second)
	validator := identity.NewAgentValidator("https://idp.example", idpPub)
	_, wlPub := mustKeyPair(t)

	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://example/agent",
		Role:        identity.RoleExecutor,
		WorkloadKey: wlPub,
	})
	if _, err := validator.Validate(tok); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestAgentToken_IssuerMismatch(t *testing.T) {
	idpPriv, idpPub := mustKeyPair(t)
	issuer := identity.NewAgentIssuer("https://idp-a.example", idpPriv, time.Hour)
	validator := identity.NewAgentValidator("https://idp-b.example", idpPub)
	_, wlPub := mustKeyPair(t)

	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://example/agent",
		Role:        identity.RoleExecutor,
		WorkloadKey: wlPub,
	})
	if _, err := validator.Validate(tok); err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestAgentToken_MissingFields(t *testing.T) {
	issuer, _, _ := newIssuerValidator(t)
	_, wlPub := mustKeyPair(t)

	if _, err := issuer.Issue(identity.IssueOptions{Role: identity.RoleExecutor, WorkloadKey: wlPub}); err == nil {
		t.Error("expected error for missing subject")
	}
	if _, err := issuer.Issue(identity.IssueOptions{Subject: "spiffe://x/y", WorkloadKey: wlPub}); err == nil {
		t.Error("expected error for missing role")
	}
	if _, err := issuer.Issue(identity.IssueOptions{Subject: "spiffe://x/y", Role: identity.RoleExecutor}); err == nil {
		t.Error("expected error for missing workload key")
	}
}

// ── AgentChain tests ──────────────────────────────────────────────────────────

func issueChainToken(t *testing.T, issuer *identity.AgentIssuer, depth int, pub *ecdsa.PublicKey) string {
	t.Helper()
	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://cloud-a.example/agent/node",
		Role:        identity.RoleExecutor,
		ChainDepth:  depth,
		WorkloadKey: pub,
	})
	if err != nil {
		t.Fatalf("Issue depth %d: %v", depth, err)
	}
	return tok
}

func TestAgentChain_ParseAndString(t *testing.T) {
	chain := identity.AgentChain{"tok1", "tok2", "tok3"}
	s := chain.String()
	parsed, err := identity.ParseChain(s)
	if err != nil {
		t.Fatalf("ParseChain: %v", err)
	}
	if parsed.String() != s {
		t.Errorf("round-trip mismatch: %q != %q", parsed.String(), s)
	}
}

func TestAgentChain_Extend(t *testing.T) {
	chain := identity.AgentChain{"tok1"}
	extended, err := chain.Extend("tok2")
	if err != nil {
		t.Fatalf("Extend: %v", err)
	}
	if extended.Len() != 2 {
		t.Errorf("expected len 2 got %d", extended.Len())
	}
	// original unchanged
	if chain.Len() != 1 {
		t.Error("original chain was mutated")
	}
}

func TestAgentChain_HashStable(t *testing.T) {
	chain := identity.AgentChain{"abc", "def"}
	h1 := chain.Hash()
	h2 := chain.Hash()
	if h1 != h2 {
		t.Error("Hash is not stable")
	}
	chain2 := identity.AgentChain{"abc", "xyz"}
	if chain.Hash() == chain2.Hash() {
		t.Error("different chains should have different hashes")
	}
}

func TestAgentChain_Validate(t *testing.T) {
	issuer, validator, _ := newIssuerValidator(t)
	_, pub0 := mustKeyPair(t)
	_, pub1 := mustKeyPair(t)

	tok0 := issueChainToken(t, issuer, 0, pub0)
	tok1 := issueChainToken(t, issuer, 1, pub1)

	chain := identity.AgentChain{tok0, tok1}
	validators := map[string]*identity.AgentValidator{
		"https://idp.example": validator,
	}

	results, err := chain.Validate(validators)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results got %d", len(results))
	}
	if results[0].Claims.ChainDepth != 0 || results[1].Claims.ChainDepth != 1 {
		t.Error("chain depths incorrect")
	}
}

func TestAgentChain_WrongDepthOrder(t *testing.T) {
	issuer, validator, _ := newIssuerValidator(t)
	_, pub := mustKeyPair(t)

	tok0 := issueChainToken(t, issuer, 0, pub)
	tok2 := issueChainToken(t, issuer, 2, pub) // skipped depth 1

	chain := identity.AgentChain{tok0, tok2}
	validators := map[string]*identity.AgentValidator{
		"https://idp.example": validator,
	}
	if _, err := chain.Validate(validators); err == nil {
		t.Error("expected error for wrong chain_depth order")
	}
}

// ── AgentProofToken tests ─────────────────────────────────────────────────────

func buildChainAndProof(t *testing.T) (identity.AgentChain, *ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	issuer, _, _ := newIssuerValidator(t)
	wlPriv, wlPub := mustKeyPair(t)
	tok := issueChainToken(t, issuer, 0, wlPub)
	chain := identity.AgentChain{tok}
	return chain, wlPriv, wlPub
}

func TestAgentProof_HappyPath(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api/data",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	pv := identity.NewProofValidator()
	claims, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api/data",
		WorkloadKey: wlPub,
		CheckReplay: false,
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.ChainHash != chain.Hash() {
		t.Error("chain_hash mismatch")
	}
}

func TestAgentProof_AudienceMismatch(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api/data",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	pv := identity.NewProofValidator()
	if _, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api/OTHER",
		WorkloadKey: wlPub,
	}); err == nil {
		t.Error("expected error for aud mismatch")
	}
}

func TestAgentProof_ChainHashMismatch(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)
	issuer, _, _ := newIssuerValidator(t)
	_, pub2 := mustKeyPair(t)
	tok2 := issueChainToken(t, issuer, 0, pub2)
	differentChain := identity.AgentChain{tok2}

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	pv := identity.NewProofValidator()
	if _, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       differentChain, // different chain → different hash
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
	}); err == nil {
		t.Error("expected error for chain_hash mismatch")
	}
}

func TestAgentProof_Expired(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
		TTL:         -1 * time.Second,
	})

	pv := identity.NewProofValidator()
	if _, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
	}); err == nil {
		t.Error("expected error for expired proof")
	}
}

func TestAgentProof_ReplayDetection(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	pv := identity.NewProofValidator()
	vopts := identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
		CheckReplay: true,
	}

	if _, err := pv.Validate(vopts); err != nil {
		t.Fatalf("first validation failed: %v", err)
	}
	if _, err := pv.Validate(vopts); err == nil {
		t.Error("expected replay error on second use of same jti")
	}
}

func TestAgentProof_WrongSigningKey(t *testing.T) {
	chain, wlPriv, _ := buildChainAndProof(t)
	_, wrongPub := mustKeyPair(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	pv := identity.NewProofValidator()
	if _, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wrongPub,
	}); err == nil {
		t.Error("expected error for wrong signing key")
	}
}

func TestAgentProof_TxnTokenBinding_HappyPath(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)
	txnToken := "fake.txn.token.for.test"

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
		TxnToken:    txnToken,
	})
	if err != nil {
		t.Fatalf("GenerateProof with TxnToken: %v", err)
	}

	pv := identity.NewProofValidator()
	claims, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
		TxnToken:    txnToken,
	})
	if err != nil {
		t.Fatalf("Validate with TxnToken: %v", err)
	}
	if claims.Tth == "" {
		t.Error("expected tth claim to be set in proof")
	}
}

func TestAgentProof_TxnTokenBinding_Mismatch(t *testing.T) {
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
		TxnToken:    "original.txn.token",
	})

	pv := identity.NewProofValidator()
	_, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
		TxnToken:    "different.txn.token",
	})
	if err == nil {
		t.Error("expected error for tth mismatch")
	}
}

func TestAgentProof_TxnTokenBinding_NotRequired(t *testing.T) {
	// Proof without tth should still validate when no TxnToken is presented.
	chain, wlPriv, wlPub := buildChainAndProof(t)

	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   "https://svc-b.example/api",
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	pv := identity.NewProofValidator()
	_, err := pv.Validate(identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  "https://svc-b.example/api",
		WorkloadKey: wlPub,
	})
	if err != nil {
		t.Fatalf("expected validation without tth to succeed: %v", err)
	}
}
