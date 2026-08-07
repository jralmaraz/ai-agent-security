package identitychaining_test

import (
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/identitychaining"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
	"github.com/golang-jwt/jwt/v5"
)

const (
	domainAIssuer   = "https://as.cloud-a.example"
	domainBEndpoint = "https://as.cloud-b.example/token"
	agentSPIFFEID   = "spiffe://cloud-a.example/agents/orchestrator"
)

// issueAgentToken creates an AgentToken for domain A signed by idpKP.
func issueAgentToken(t *testing.T, idpKP, agentKP *keys.ECKeyPair) string {
	t.Helper()
	issuer := identity.NewAgentIssuer(domainAIssuer, idpKP.Private, time.Hour)
	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     agentSPIFFEID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue AgentToken: %v", err)
	}
	return tok
}

func setup(t *testing.T) (agentToken string, grantIssuer *identitychaining.GrantIssuer, domainAKP *keys.ECKeyPair) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ = keys.GenerateECKeyPair()

	agentToken = issueAgentToken(t, idpKP, agentKP)
	validator := identity.NewAgentValidator(domainAIssuer, idpKP.Public)
	grantIssuer = identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, 5*time.Minute)
	return
}

func TestIdentityChaining_HappyPath(t *testing.T) {
	agentToken, grantIssuer, domainAKP := setup(t)

	grant, err := grantIssuer.Issue(agentToken, domainBEndpoint)
	if err != nil {
		t.Fatalf("Issue grant: %v", err)
	}

	validator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	claims, err := validator.Validate(grant, domainBEndpoint)
	if err != nil {
		t.Fatalf("Validate grant: %v", err)
	}
	if claims.Subject != agentSPIFFEID {
		t.Errorf("sub: want %q got %q", agentSPIFFEID, claims.Subject)
	}
	if claims.Issuer != domainAIssuer {
		t.Errorf("iss: want %q got %q", domainAIssuer, claims.Issuer)
	}
}

func TestIdentityChaining_TypHeader(t *testing.T) {
	agentToken, grantIssuer, _ := setup(t)
	grant, _ := grantIssuer.Issue(agentToken, domainBEndpoint)

	p := jwt.NewParser()
	var c identitychaining.GrantClaims
	tok, _, err := p.ParseUnverified(grant, &c)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	typ, _ := tok.Header["typ"].(string)
	if typ != "jwt-authz-grant" {
		t.Errorf("typ: want jwt-authz-grant got %q", typ)
	}
}

func TestIdentityChaining_AudienceMismatch(t *testing.T) {
	agentToken, grantIssuer, domainAKP := setup(t)
	grant, _ := grantIssuer.Issue(agentToken, domainBEndpoint)

	validator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	_, err := validator.Validate(grant, "https://different-as.example/token")
	if err == nil {
		t.Error("expected error for audience mismatch")
	}
}

func TestIdentityChaining_WrongSigningKey(t *testing.T) {
	agentToken, grantIssuer, _ := setup(t)
	grant, _ := grantIssuer.Issue(agentToken, domainBEndpoint)

	otherKP, _ := keys.GenerateECKeyPair()
	validator := identitychaining.NewGrantValidator(domainAIssuer, otherKP.Public)
	if _, err := validator.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for wrong signing key")
	}
}

func TestIdentityChaining_ExpiredGrant(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	agentToken := issueAgentToken(t, idpKP, agentKP)
	validator := identity.NewAgentValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, -time.Second)

	grant, _ := grantIssuer.Issue(agentToken, domainBEndpoint)

	gv := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	if _, err := gv.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for expired grant")
	}
}

func TestIdentityChaining_IssuerMismatch(t *testing.T) {
	agentToken, grantIssuer, domainAKP := setup(t)
	grant, _ := grantIssuer.Issue(agentToken, domainBEndpoint)

	// Validator configured for wrong issuer
	validator := identitychaining.NewGrantValidator("https://imposter.example", domainAKP.Public)
	if _, err := validator.Validate(grant, domainBEndpoint); err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestIdentityChaining_InvalidAgentToken(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	validator := identity.NewAgentValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, validator, 5*time.Minute)

	// Tampered AgentToken — validator should reject it
	if _, err := grantIssuer.Issue("not.a.valid.agent-token", domainBEndpoint); err == nil {
		t.Error("expected error for invalid AgentToken")
	}
}

func TestIdentityChaining_MissingSubjectToken(t *testing.T) {
	_, grantIssuer, _ := setup(t)
	if _, err := grantIssuer.Issue("", domainBEndpoint); err == nil {
		t.Error("expected error for empty subject token")
	}
}

func TestIdentityChaining_MissingTargetAudience(t *testing.T) {
	agentToken, grantIssuer, _ := setup(t)
	if _, err := grantIssuer.Issue(agentToken, ""); err == nil {
		t.Error("expected error for empty target audience")
	}
}

func TestIdentityChaining_ActClaim(t *testing.T) {
	// RFC 8693 §4.1: when the delegating agent (sub) and the calling agent (act.sub)
	// differ — e.g. orchestrator delegates to sub-agent for a cross-domain call.
	agentToken, grantIssuer, domainAKP := setup(t)

	actor := &identitychaining.ActorClaims{
		Sub: "spiffe://cloud-a.example/agents/sub-agent",
	}
	grant, err := grantIssuer.Issue(agentToken, domainBEndpoint, actor)
	if err != nil {
		t.Fatalf("Issue grant with actor: %v", err)
	}

	validator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	claims, err := validator.Validate(grant, domainBEndpoint)
	if err != nil {
		t.Fatalf("Validate grant: %v", err)
	}
	if claims.Act == nil {
		t.Fatal("expected act claim in grant")
	}
	if claims.Act.Sub != actor.Sub {
		t.Errorf("act.sub: want %q got %q", actor.Sub, claims.Act.Sub)
	}
	// sub must remain the original orchestrator SPIFFE ID
	if claims.Subject != agentSPIFFEID {
		t.Errorf("sub must be original agent SPIFFE ID, got %q", claims.Subject)
	}
}

func TestIdentityChaining_EndToEnd(t *testing.T) {
	// Full cross-domain flow:
	// 1. Domain A issues AgentToken to agent
	// 2. Agent presents AgentToken to domain A's GrantIssuer → gets JWT grant
	// 3. Agent presents grant to domain B's GrantValidator → domain B extracts SPIFFE ID
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	domainAKP, _ := keys.GenerateECKeyPair()

	// Step 1: issue AgentToken
	agentIssuer := identity.NewAgentIssuer(domainAIssuer, idpKP.Private, time.Hour)
	agentToken, err := agentIssuer.Issue(identity.IssueOptions{
		Subject:     agentSPIFFEID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue AgentToken: %v", err)
	}

	// Step 2: exchange AgentToken for JWT grant at domain A's AS
	agentValidator := identity.NewAgentValidator(domainAIssuer, idpKP.Public)
	grantIssuer := identitychaining.NewGrantIssuer(domainAIssuer, domainAKP.Private, agentValidator, 5*time.Minute)
	grant, err := grantIssuer.Issue(agentToken, domainBEndpoint)
	if err != nil {
		t.Fatalf("Issue grant: %v", err)
	}

	// Step 3: domain B validates the grant
	grantValidator := identitychaining.NewGrantValidator(domainAIssuer, domainAKP.Public)
	claims, err := grantValidator.Validate(grant, domainBEndpoint)
	if err != nil {
		t.Fatalf("Validate grant: %v", err)
	}

	if claims.Subject != agentSPIFFEID {
		t.Errorf("expected SPIFFE ID %q, got %q", agentSPIFFEID, claims.Subject)
	}
}
