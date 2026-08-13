package obo_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/jralmaraz/ai-agent-security/pkg/keys"
	"github.com/jralmaraz/ai-agent-security/pkg/obo"
)

const (
	sdIdpIssuer   = "https://idp.example.com"
	sdASIssuer    = "https://as.example.com"
	sdAgentID     = "spiffe://example.com/agents/booking-assistant"
	sdUserID      = "user:alice@example.com"
	sdUserEmail   = "alice@example.com"
	sdGivenName   = "Alice"
	sdUserScope   = "read:calendar write:booking"
	sdResourceURL = "https://booking-service.example.com"
)

// sdSetup creates key pairs and returns an SDUserIssuer and SDUserValidator
// sharing the same IdP key pair.
func sdSetup(t *testing.T) (*obo.SDUserIssuer, *obo.SDUserValidator, *keys.ECKeyPair) {
	t.Helper()
	kp, _ := keys.GenerateECKeyPair()
	issuer := obo.NewSDUserIssuer(sdIdpIssuer, kp.Private, time.Hour)
	validator := obo.NewSDUserValidator(sdIdpIssuer, kp.Public)
	return issuer, validator, kp
}

// ── Wire format tests ─────────────────────────────────────────────────────────

func TestSDJWT_WireFormat(t *testing.T) {
	issuer, _, _ := sdSetup(t)
	tok, err := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	wire := tok.Wire()
	parts := strings.Split(wire, "~")
	// Expect: JWT ~ disc1 ~ disc2 ~ ""  (4 parts minimum)
	if len(parts) < 4 {
		t.Fatalf("expected at least 4 parts (JWT + 2 disclosures + trailing empty), got %d", len(parts))
	}
	if parts[0] == "" {
		t.Error("JWT part must not be empty")
	}
	if parts[len(parts)-1] != "" {
		t.Errorf("last part must be empty (trailing ~), got %q", parts[len(parts)-1])
	}
}

func TestSDJWT_IssueContainsNoRawPII(t *testing.T) {
	issuer, _, _ := sdSetup(t)
	tok, err := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// The JWT part (before first ~) must NOT contain raw email or given_name values.
	jwtPart := strings.Split(tok.Wire(), "~")[0]
	if strings.Contains(jwtPart, sdUserEmail) {
		t.Error("JWT part must not contain raw email — only the disclosure digest")
	}
	if strings.Contains(jwtPart, sdGivenName) {
		t.Error("JWT part must not contain raw given_name — only the disclosure digest")
	}
}

// ── SDUserValidator tests ─────────────────────────────────────────────────────

func TestSDJWT_ValidateFullPresentation(t *testing.T) {
	issuer, validator, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	result, err := validator.Validate(tok.Wire(), sdASIssuer)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != sdUserID {
		t.Errorf("Subject: want %q got %q", sdUserID, result.Subject)
	}
	if result.Scope != sdUserScope {
		t.Errorf("Scope: want %q got %q", sdUserScope, result.Scope)
	}
	if result.RevealedClaims["email"] != sdUserEmail {
		t.Errorf("email: want %q got %q", sdUserEmail, result.RevealedClaims["email"])
	}
	if result.RevealedClaims["given_name"] != sdGivenName {
		t.Errorf("given_name: want %q got %q", sdGivenName, result.RevealedClaims["given_name"])
	}
}

func TestSDJWT_PresentEmailOnly(t *testing.T) {
	issuer, validator, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	// Agent reveals only email — given_name stays private.
	wire := tok.Present([]string{"email"})
	result, err := validator.Validate(wire, sdASIssuer)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.RevealedClaims["email"] != sdUserEmail {
		t.Errorf("email: want %q got %q", sdUserEmail, result.RevealedClaims["email"])
	}
	if _, ok := result.RevealedClaims["given_name"]; ok {
		t.Error("given_name must not be revealed when omitted from presentation")
	}
}

func TestSDJWT_PresentNoDisclosures(t *testing.T) {
	issuer, validator, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	// Agent reveals nothing — sub and scope still present (non-SD claims).
	wire := tok.Present(nil)
	result, err := validator.Validate(wire, sdASIssuer)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != sdUserID {
		t.Errorf("Subject: want %q got %q", sdUserID, result.Subject)
	}
	if len(result.RevealedClaims) != 0 {
		t.Errorf("expected no revealed claims, got %v", result.RevealedClaims)
	}
}

func TestSDJWT_ValidateWrongAudience(t *testing.T) {
	issuer, validator, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	_, err := validator.Validate(tok.Wire(), "https://wrong.example.com")
	if err == nil {
		t.Fatal("expected error for wrong audience, got nil")
	}
}

func TestSDJWT_ValidateWrongKey(t *testing.T) {
	issuer, _, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	wrongKP, _ := keys.GenerateECKeyPair()
	validator := obo.NewSDUserValidator(sdIdpIssuer, wrongKP.Public)
	_, err := validator.Validate(tok.Wire(), sdASIssuer)
	if err == nil {
		t.Fatal("expected error for wrong signing key, got nil")
	}
}

func TestSDJWT_ValidateForgedDisclosure(t *testing.T) {
	issuer, validator, _ := sdSetup(t)
	tok, _ := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	// Forge a disclosure wire the IdP never issued — its digest won't be in _sd.
	forged := base64.RawURLEncoding.EncodeToString(
		[]byte(`["fakesalt","phone_number","+1-555-0100"]`),
	)
	// Inject the forged disclosure into an otherwise-valid presentation.
	wire := tok.Present([]string{"email"}) + forged + "~"
	_, err := validator.Validate(wire, sdASIssuer)
	if err == nil {
		t.Fatal("expected error for forged disclosure, got nil")
	}
}

func TestSDJWT_ValidateMissingTildeSeparator(t *testing.T) {
	_, validator, _ := sdSetup(t)
	_, err := validator.Validate("not.an.sdjwt", sdASIssuer)
	if err == nil {
		t.Fatal("expected error for missing ~ separator, got nil")
	}
}

func TestSDJWT_ValidateEmptyPresentation(t *testing.T) {
	_, validator, _ := sdSetup(t)
	_, err := validator.Validate("", sdASIssuer)
	if err == nil {
		t.Fatal("expected error for empty presentation, got nil")
	}
}

func TestSDJWT_MissingSubject(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	issuer := obo.NewSDUserIssuer(sdIdpIssuer, kp.Private, time.Hour)
	_, err := issuer.Issue("", sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	if err == nil {
		t.Fatal("expected error for empty sub, got nil")
	}
}

func TestSDJWT_MissingAudience(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	issuer := obo.NewSDUserIssuer(sdIdpIssuer, kp.Private, time.Hour)
	_, err := issuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, "")
	if err == nil {
		t.Fatal("expected error for empty audience, got nil")
	}
}

// ── SD-JWT + OBO integration tests ───────────────────────────────────────────

// sdOBOSetup builds the full stack for SD-JWT OBO integration tests.
func sdOBOSetup(t *testing.T) (
	agentToken string,
	sdIssuer *obo.SDUserIssuer,
	oboIssuer *obo.OBOIssuer,
	oboKP *keys.ECKeyPair,
) {
	t.Helper()
	idpKP, _ := keys.GenerateECKeyPair()
	agentIdpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	oboKP, _ = keys.GenerateECKeyPair()

	agentIssuer := identity.NewAgentIssuer(sdASIssuer, agentIdpKP.Private, time.Hour)
	tok, err := agentIssuer.Issue(identity.IssueOptions{
		Subject:     sdAgentID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue AgentToken: %v", err)
	}
	agentToken = tok

	sdIssuer = obo.NewSDUserIssuer(sdIdpIssuer, idpKP.Private, time.Hour)
	sdUserValidator := obo.NewSDUserValidator(sdIdpIssuer, idpKP.Public)

	agentValidator := identity.NewAgentValidator(sdASIssuer, agentIdpKP.Public)
	// userValidator is nil — only the SD-JWT path is used in these tests.
	oboIssuer = obo.NewOBOIssuer(sdASIssuer, oboKP.Private, agentValidator, nil, 5*time.Minute).
		WithSDUserValidator(sdUserValidator)
	return
}

func TestOBO_SDJWT_EmailRevealedInOBOToken(t *testing.T) {
	agentToken, sdIssuer, oboIssuer, oboKP := sdOBOSetup(t)

	userTok, err := sdIssuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	if err != nil {
		t.Fatalf("SDUserIssuer.Issue: %v", err)
	}
	// Agent reveals only email; given_name stays private.
	presentation := userTok.Present([]string{"email"})

	oboTok, err := oboIssuer.Issue(agentToken, presentation, sdResourceURL, "read:calendar")
	if err != nil {
		t.Fatalf("OBOIssuer.Issue: %v", err)
	}

	validator := obo.NewOBOValidator(sdASIssuer, oboKP.Public)
	result, err := validator.Validate(oboTok, sdResourceURL)
	if err != nil {
		t.Fatalf("Validate OBO token: %v", err)
	}
	if result.UserID != sdUserID {
		t.Errorf("UserID: want %q got %q", sdUserID, result.UserID)
	}
	if result.AgentID != sdAgentID {
		t.Errorf("AgentID: want %q got %q", sdAgentID, result.AgentID)
	}
	if result.Email != sdUserEmail {
		t.Errorf("Email: want %q got %q", sdUserEmail, result.Email)
	}
	if result.Scope != "read:calendar" {
		t.Errorf("Scope: want %q got %q", "read:calendar", result.Scope)
	}
}

func TestOBO_SDJWT_EmailNotRevealedIsEmpty(t *testing.T) {
	agentToken, sdIssuer, oboIssuer, oboKP := sdOBOSetup(t)

	userTok, _ := sdIssuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	// Agent reveals nothing.
	presentation := userTok.Present(nil)

	oboTok, err := oboIssuer.Issue(agentToken, presentation, sdResourceURL, "read:calendar")
	if err != nil {
		t.Fatalf("OBOIssuer.Issue: %v", err)
	}

	validator := obo.NewOBOValidator(sdASIssuer, oboKP.Public)
	result, err := validator.Validate(oboTok, sdResourceURL)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Email != "" {
		t.Errorf("Email must be empty when not revealed, got %q", result.Email)
	}
}

func TestOBO_SDJWT_ScopeSubsetEnforced(t *testing.T) {
	agentToken, sdIssuer, oboIssuer, _ := sdOBOSetup(t)

	userTok, _ := sdIssuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)
	presentation := userTok.Present([]string{"email"})

	// write:billing is NOT in sdUserScope — must be rejected.
	_, err := oboIssuer.Issue(agentToken, presentation, sdResourceURL, "write:billing")
	if err == nil {
		t.Fatal("expected scope-not-subset error, got nil")
	}
}

func TestOBO_SDJWT_NoSDValidatorRejectsSDToken(t *testing.T) {
	idpKP, _ := keys.GenerateECKeyPair()
	agentIdpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	oboKP, _ := keys.GenerateECKeyPair()

	agentIssuer := identity.NewAgentIssuer(sdASIssuer, agentIdpKP.Private, time.Hour)
	agentToken, _ := agentIssuer.Issue(identity.IssueOptions{
		Subject:     sdAgentID,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})

	sdIssuer := obo.NewSDUserIssuer(sdIdpIssuer, idpKP.Private, time.Hour)
	userTok, _ := sdIssuer.Issue(sdUserID, sdUserEmail, sdGivenName, sdUserScope, sdASIssuer)

	// OBOIssuer WITHOUT an SDUserValidator — must reject an SD-JWT presentation.
	agentValidator := identity.NewAgentValidator(sdASIssuer, agentIdpKP.Public)
	plainUserValidator := obo.NewUserValidator(sdIdpIssuer, idpKP.Public)
	oboIssuer := obo.NewOBOIssuer(sdASIssuer, oboKP.Private, agentValidator, plainUserValidator, 5*time.Minute)

	_, err := oboIssuer.Issue(agentToken, userTok.Wire(), sdResourceURL, "read:calendar")
	if err == nil {
		t.Fatal("expected error: SD-JWT presented but no SDUserValidator configured")
	}
}
