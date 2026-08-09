package obo_test

import (
	"testing"
	"time"

	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/jralmaraz/ai-agent-security/pkg/keys"
	"github.com/jralmaraz/ai-agent-security/pkg/obo"
)

const (
	idpIssuer    = "https://idp.example.com"
	asIssuer     = "https://as.example.com"
	agentID      = "spiffe://example.com/agents/booking-assistant"
	userID       = "user:alice@example.com"
	userEmail    = "alice@example.com"
	userScope    = "read:calendar write:booking read:contacts"
	resourceURL  = "https://booking-service.example.com"
)

// setup creates key pairs and the full OBO stack: IdP, agent validator, OBO issuer.
func setup(t *testing.T) (
	agentToken string,
	userToken string,
	issuer *obo.OBOIssuer,
	oboKP *keys.ECKeyPair,
) {
	t.Helper()

	// IdP key pair — signs user identity tokens.
	idpKP, _ := keys.GenerateECKeyPair()
	// Agent IdP key pair — signs AgentTokens.
	agentIdpKP, _ := keys.GenerateECKeyPair()
	// Agent's own workload key.
	agentKP, _ := keys.GenerateECKeyPair()
	// OBO AS key pair — signs OBO delegated tokens.
	oboKP, _ = keys.GenerateECKeyPair()

	// Issue an AgentToken.
	agentIssuer := identity.NewAgentIssuer(asIssuer, agentIdpKP.Private, time.Hour)
	tok, err := agentIssuer.Issue(identity.IssueOptions{
		Subject:     agentID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue AgentToken: %v", err)
	}
	agentToken = tok

	// Issue a user identity token.
	userIssuer := obo.NewUserIssuer(idpIssuer, idpKP.Private, time.Hour)
	uTok, err := userIssuer.Issue(userID, userEmail, userScope, asIssuer)
	if err != nil {
		t.Fatalf("Issue user token: %v", err)
	}
	userToken = uTok

	agentValidator := identity.NewAgentValidator(asIssuer, agentIdpKP.Public)
	userValidator := obo.NewUserValidator(idpIssuer, idpKP.Public)
	issuer = obo.NewOBOIssuer(asIssuer, oboKP.Private, agentValidator, userValidator, 5*time.Minute)
	return
}

// TestOBO_HappyPath verifies full OBO issuance and validation.
func TestOBO_HappyPath(t *testing.T) {
	agentToken, userToken, issuer, oboKP := setup(t)

	oboTok, err := issuer.Issue(agentToken, userToken, resourceURL, "read:calendar write:booking")
	if err != nil {
		t.Fatalf("Issue OBO token: %v", err)
	}

	validator := obo.NewOBOValidator(asIssuer, oboKP.Public)
	result, err := validator.Validate(oboTok, resourceURL)
	if err != nil {
		t.Fatalf("Validate OBO token: %v", err)
	}

	if result.UserID != userID {
		t.Errorf("UserID: want %q got %q", userID, result.UserID)
	}
	if result.AgentID != agentID {
		t.Errorf("AgentID: want %q got %q", agentID, result.AgentID)
	}
	if result.Scope != "read:calendar write:booking" {
		t.Errorf("Scope: want %q got %q", "read:calendar write:booking", result.Scope)
	}
}

// TestOBO_EmptyScopeInheritsUserScope verifies that passing "" inherits all user scopes.
func TestOBO_EmptyScopeInheritsUserScope(t *testing.T) {
	agentToken, userToken, issuer, oboKP := setup(t)

	oboTok, err := issuer.Issue(agentToken, userToken, resourceURL, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	validator := obo.NewOBOValidator(asIssuer, oboKP.Public)
	result, err := validator.Validate(oboTok, resourceURL)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Scope != userScope {
		t.Errorf("Scope: want %q got %q", userScope, result.Scope)
	}
}

// TestOBO_ScopeNotSubset verifies that requesting a scope outside the user's grant is rejected.
func TestOBO_ScopeNotSubset(t *testing.T) {
	agentToken, userToken, issuer, _ := setup(t)

	_, err := issuer.Issue(agentToken, userToken, resourceURL, "write:billing")
	if err == nil {
		t.Fatal("expected error for out-of-scope request, got nil")
	}
}

// TestOBO_InvalidAgentToken verifies that a tampered agent token is rejected.
func TestOBO_InvalidAgentToken(t *testing.T) {
	_, userToken, issuer, _ := setup(t)

	_, err := issuer.Issue("not.a.valid.token", userToken, resourceURL, "read:calendar")
	if err == nil {
		t.Fatal("expected error for invalid agent token, got nil")
	}
}

// TestOBO_InvalidUserToken verifies that a tampered user token is rejected.
func TestOBO_InvalidUserToken(t *testing.T) {
	agentToken, _, issuer, _ := setup(t)

	_, err := issuer.Issue(agentToken, "not.a.valid.token", resourceURL, "read:calendar")
	if err == nil {
		t.Fatal("expected error for invalid user token, got nil")
	}
}

// TestOBO_WrongAudience verifies that validation fails when audience doesn't match.
func TestOBO_WrongAudience(t *testing.T) {
	agentToken, userToken, issuer, oboKP := setup(t)

	oboTok, err := issuer.Issue(agentToken, userToken, resourceURL, "read:calendar")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	validator := obo.NewOBOValidator(asIssuer, oboKP.Public)
	_, err = validator.Validate(oboTok, "https://wrong-service.example.com")
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

// TestOBO_ExpiredToken verifies that an expired OBO token is rejected.
func TestOBO_ExpiredToken(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	agentIdpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	oboKP, _ := keys.GenerateECKeyPair()

	agentIssuer := identity.NewAgentIssuer(asIssuer, agentIdpKP.Private, time.Hour)
	agentToken, _ := agentIssuer.Issue(identity.IssueOptions{
		Subject:     agentID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})

	userIssuer := obo.NewUserIssuer(idpIssuer, idpKP.Private, time.Hour)
	userToken, _ := userIssuer.Issue(userID, userEmail, userScope, asIssuer)

	agentValidator := identity.NewAgentValidator(asIssuer, agentIdpKP.Public)
	userValidator := obo.NewUserValidator(idpIssuer, idpKP.Public)
	// Negative TTL → immediately expired.
	issuer := obo.NewOBOIssuer(asIssuer, oboKP.Private, agentValidator, userValidator, -time.Second)

	oboTok, err := issuer.Issue(agentToken, userToken, resourceURL, "read:calendar")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	validator := obo.NewOBOValidator(asIssuer, oboKP.Public)
	_, err = validator.Validate(oboTok, resourceURL)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

// TestOBO_WrongIssuerKey verifies that a token signed by a different key is rejected.
func TestOBO_WrongIssuerKey(t *testing.T) {
	agentToken, userToken, issuer, _ := setup(t)

	oboTok, err := issuer.Issue(agentToken, userToken, resourceURL, "read:calendar")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	wrongKP, _ := keys.GenerateECKeyPair()
	validator := obo.NewOBOValidator(asIssuer, wrongKP.Public)
	_, err = validator.Validate(oboTok, resourceURL)
	if err == nil {
		t.Fatal("expected error for wrong issuer key, got nil")
	}
}

// TestOBO_BothIdentitiesInResult verifies act.sub and sub are correctly populated.
func TestOBO_BothIdentitiesInResult(t *testing.T) {
	agentToken, userToken, issuer, oboKP := setup(t)

	oboTok, _ := issuer.Issue(agentToken, userToken, resourceURL, "read:calendar")
	validator := obo.NewOBOValidator(asIssuer, oboKP.Public)
	result, err := validator.Validate(oboTok, resourceURL)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Both identities must be present — this is OBO's core value.
	if result.UserID == "" {
		t.Error("UserID (sub) must not be empty")
	}
	if result.AgentID == "" {
		t.Error("AgentID (act.sub) must not be empty")
	}
	if result.UserID == result.AgentID {
		t.Error("UserID and AgentID must be distinct")
	}
}

// TestUserIssuer_MissingSubject verifies sub is required.
func TestUserIssuer_MissingSubject(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	issuer := obo.NewUserIssuer(idpIssuer, kp.Private, time.Hour)
	_, err := issuer.Issue("", userEmail, userScope, asIssuer)
	if err == nil {
		t.Fatal("expected error for empty sub, got nil")
	}
}
