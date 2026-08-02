package spiffeclientauth_test

import (
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/spiffeclientauth"
)

const (
	issuerID  = "https://idp.agent-mesh.example"
	agentSPID = "spiffe://agent-mesh.example/agents/orchestrator"
)

func setup(t *testing.T) (agentToken string, auth *spiffeclientauth.Authenticator) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()

	issuer := identity.NewAgentIssuer(issuerID, idpKP.Private, time.Hour)
	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     agentSPID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue AgentToken: %v", err)
	}

	validator := identity.NewAgentValidator(issuerID, idpKP.Public)
	auth = spiffeclientauth.NewAuthenticator(issuerID, validator, time.Hour)
	return tok, auth
}

func defaultReq(agentToken string) spiffeclientauth.AuthRequest {
	return spiffeclientauth.AuthRequest{
		ClientAssertion:     agentToken,
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
		Scope:               "read:tasks write:results",
	}
}

func TestSPIFFEClientAuth_HappyPath(t *testing.T) {
	agentToken, auth := setup(t)
	tok, err := auth.Authenticate(defaultReq(agentToken))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty access_token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type: want Bearer got %q", tok.TokenType)
	}
	if tok.Sub != agentSPID {
		t.Errorf("sub: want %q got %q", agentSPID, tok.Sub)
	}
	if tok.ExpiresIn <= 0 {
		t.Error("expected positive expires_in")
	}
}

func TestSPIFFEClientAuth_TokensAreUnique(t *testing.T) {
	agentToken, auth := setup(t)
	req := defaultReq(agentToken)
	t1, _ := auth.Authenticate(req)
	t2, _ := auth.Authenticate(req)
	if t1.Token == t2.Token {
		t.Error("expected distinct access tokens on each call")
	}
}

func TestSPIFFEClientAuth_WrongAssertionType(t *testing.T) {
	agentToken, auth := setup(t)
	req := defaultReq(agentToken)
	req.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"
	if _, err := auth.Authenticate(req); err == nil {
		t.Error("expected error for wrong assertion type")
	}
}

func TestSPIFFEClientAuth_EmptyAssertion(t *testing.T) {
	_, auth := setup(t)
	req := spiffeclientauth.AuthRequest{
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
	}
	if _, err := auth.Authenticate(req); err == nil {
		t.Error("expected error for empty client_assertion")
	}
}

func TestSPIFFEClientAuth_TamperedToken(t *testing.T) {
	agentToken, auth := setup(t)
	if _, err := auth.Authenticate(defaultReq(agentToken + "tampered")); err == nil {
		t.Error("expected error for tampered AgentToken")
	}
}

func TestSPIFFEClientAuth_ExpiredToken(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()

	issuer := identity.NewAgentIssuer(issuerID, idpKP.Private, -time.Second)
	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     agentSPID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})

	validator := identity.NewAgentValidator(issuerID, idpKP.Public)
	auth := spiffeclientauth.NewAuthenticator(issuerID, validator, time.Hour)

	if _, err := auth.Authenticate(defaultReq(tok)); err == nil {
		t.Error("expected error for expired AgentToken")
	}
}

func TestSPIFFEClientAuth_WrongIssuer(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()

	issuer := identity.NewAgentIssuer("https://idp-a.example", idpKP.Private, time.Hour)
	tok, _ := issuer.Issue(identity.IssueOptions{
		Subject:     agentSPID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})

	validator := identity.NewAgentValidator("https://idp-b.example", idpKP.Public)
	auth := spiffeclientauth.NewAuthenticator("https://idp-b.example", validator, time.Hour)

	if _, err := auth.Authenticate(defaultReq(tok)); err == nil {
		t.Error("expected error for issuer mismatch")
	}
}

func TestSPIFFEClientAuth_NoScope(t *testing.T) {
	agentToken, auth := setup(t)
	req := spiffeclientauth.AuthRequest{
		ClientAssertion:     agentToken,
		ClientAssertionType: spiffeclientauth.ClientAssertionType,
	}
	tok, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if tok.Scope != "" {
		t.Errorf("expected empty scope, got %q", tok.Scope)
	}
}
