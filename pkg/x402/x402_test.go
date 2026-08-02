package x402_test

import (
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/cb4a"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/x402"
)

const (
	idpIssuer   = "https://idp.agents.example"
	agentSVID   = "spiffe://agents.example/agent/payment-bot"
	paymentURI  = "https://api.vendor.example/v1/premium-data"
	paymentMeth = "GET"
)

// setup creates the full CB4A stack + WIMSE identity layer + PaymentGateway.
func setup(t *testing.T, asset, amount string) (
	pdp *cb4a.InMemoryPDP,
	cdp *cb4a.CDP,
	cdpKP *keys.ECKeyPair,
	gw *x402.PaymentGateway,
	agentToken string,
	agentKP *keys.ECKeyPair,
) {
	t.Helper()

	// CB4A PDP + CDP
	pdpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate PDP key: %v", err)
	}
	cdpKP, err = keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate CDP key: %v", err)
	}
	audit := cb4a.NewAuditLog()
	pdp = cb4a.NewInMemoryPDP("https://pdp.agents.example", pdpKP.Private, cb4a.DefaultPolicyRules(), 15*time.Minute, audit)
	cdp = cb4a.NewCDP(cb4a.NewInMemoryVault(), pdpKP.Public, cdpKP.Private, "https://cdp.agents.example", 15*time.Minute, audit)

	// WIMSE identity
	idpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	agentKP, err = keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	issuer := identity.NewAgentIssuer(idpIssuer, idpKP.Private, time.Hour)
	agentToken, err = issuer.Issue(identity.IssueOptions{
		Subject:     agentSVID,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		t.Fatalf("issue AgentToken: %v", err)
	}
	validator := identity.NewAgentValidator(idpIssuer, idpKP.Public)

	// Payment gateway
	gw = x402.NewPaymentGateway(cdp, cdpKP.Public, validator, asset, amount)
	return
}

// autoApprovedMint runs the full CB4A flow for a scope that the PDP auto-approves.
func autoApprovedMint(t *testing.T, pdp *cb4a.InMemoryPDP, cdp *cb4a.CDP, scope string) *cb4a.MintedCredential {
	t.Helper()
	env := &cb4a.EnvelopeClaims{
		AgentSVID: agentSVID,
		Target:    paymentURI,
		Action:    paymentMeth,
		Scope:     scope,
	}
	decisionJWT, _, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatalf("PDP evaluate: %v", err)
	}
	if decisionJWT == "" {
		t.Fatalf("expected auto-approval for scope %q", scope)
	}
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatalf("CDP mint: %v", err)
	}
	return mc
}

// hitlApprovedMint runs the full CB4A HITL flow.
func hitlApprovedMint(t *testing.T, pdp *cb4a.InMemoryPDP, cdp *cb4a.CDP, scope string) *cb4a.MintedCredential {
	t.Helper()
	env := &cb4a.EnvelopeClaims{
		AgentSVID: agentSVID,
		Target:    paymentURI,
		Action:    paymentMeth,
		Scope:     scope,
	}
	_, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatalf("PDP evaluate: %v", err)
	}
	if reqID == "" {
		t.Fatalf("expected HITL pending for scope %q", scope)
	}
	decisionJWT, err := pdp.Approve(reqID, "finance-approver")
	if err != nil {
		t.Fatalf("PDP approve: %v", err)
	}
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatalf("CDP mint: %v", err)
	}
	return mc
}

// ── Tests ──────────────────────────────────────────────────────────────────

func TestRequire_Format(t *testing.T) {
	_, _, _, gw, _, _ := setup(t, "AGENT_CREDIT", "50")
	pr := gw.Require(paymentURI)
	if pr.X402Version != 1 {
		t.Errorf("X402Version: want 1 got %d", pr.X402Version)
	}
	if len(pr.Accepts) != 1 {
		t.Fatalf("Accepts: want 1 method got %d", len(pr.Accepts))
	}
	if pr.Accepts[0].Scheme != x402.SchemeCB4ADPOP {
		t.Errorf("scheme: got %q", pr.Accepts[0].Scheme)
	}
	if pr.Accepts[0].Asset != "AGENT_CREDIT" {
		t.Errorf("asset: got %q", pr.Accepts[0].Asset)
	}
	if pr.Accepts[0].Amount != "50" {
		t.Errorf("amount: got %q", pr.Accepts[0].Amount)
	}
	if pr.Resource != paymentURI {
		t.Errorf("resource: got %q", pr.Resource)
	}
}

func TestPayment_HappyPath_AutoApproved(t *testing.T) {
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")

	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	agent := x402.NewPayingAgent(mc, agentToken)

	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.X402Version != 1 {
		t.Errorf("X402Version: got %d", payload.X402Version)
	}
	if payload.CB4AToken == "" || payload.DPoPProof == "" || payload.AgentToken == "" {
		t.Error("expected all payload fields to be non-empty")
	}

	result, err := gw.Verify(payload, paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.AgentSVID != agentSVID {
		t.Errorf("AgentSVID: want %q got %q", agentSVID, result.AgentSVID)
	}
	if result.Asset != "AGENT_CREDIT" {
		t.Errorf("Asset: got %q", result.Asset)
	}
	if result.Amount != "50" {
		t.Errorf("Amount: got %q", result.Amount)
	}
}

func TestPayment_HappyPath_HITLApproved(t *testing.T) {
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "100")

	mc := hitlApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:100")
	agent := x402.NewPayingAgent(mc, agentToken)

	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}

	result, err := gw.Verify(payload, paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.AgentSVID != agentSVID {
		t.Errorf("AgentSVID: want %q got %q", agentSVID, result.AgentSVID)
	}
	if result.Amount != "100" {
		t.Errorf("Amount: got %q", result.Amount)
	}
}

func TestPayment_MissingCB4AToken(t *testing.T) {
	_, _, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")
	payload := x402.PaymentPayload{
		X402Version: 1,
		DPoPProof:   "some-proof",
		AgentToken:  agentToken,
	}
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error for missing cb4aToken")
	}
}

func TestPayment_MissingDPoPProof(t *testing.T) {
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")
	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	payload := x402.PaymentPayload{
		X402Version: 1,
		CB4AToken:   mc.Token,
		AgentToken:  agentToken,
	}
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error for missing dpopProof")
	}
}

func TestPayment_MissingAgentToken(t *testing.T) {
	pdp, cdp, _, gw, _, _ := setup(t, "AGENT_CREDIT", "50")
	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	agent := x402.NewPayingAgent(mc, "")
	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error for missing agentToken")
	}
}

func TestPayment_TamperedCB4AToken(t *testing.T) {
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")
	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	agent := x402.NewPayingAgent(mc, agentToken)
	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	payload.CB4AToken += "tampered"
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error for tampered CB4A token")
	}
}

func TestPayment_ScopeMismatch(t *testing.T) {
	// Gateway requires AGENT_CREDIT:50, but credential has AGENT_CREDIT:100
	_, cdp, cdpKP, _, _, _ := setup(t, "AGENT_CREDIT", "50")
	// Build a separate PDP that will auto-approve 50 but we'll use it for 100
	pdpKP100, _ := keys.GenerateECKeyPair()
	audit := cb4a.NewAuditLog()
	pdp100 := cb4a.NewInMemoryPDP("https://pdp.agents.example", pdpKP100.Private, cb4a.DefaultPolicyRules(), 15*time.Minute, audit)
	cdp100 := cb4a.NewCDP(cb4a.NewInMemoryVault(), pdpKP100.Public, cdpKP.Private, "https://cdp.agents.example", 15*time.Minute, audit)
	_ = cdp
	_ = cdp100

	idpKP, _ := keys.GenerateECKeyPair()
	agentKP, _ := keys.GenerateECKeyPair()
	issuer := identity.NewAgentIssuer(idpIssuer, idpKP.Private, time.Hour)
	agentToken, _ := issuer.Issue(identity.IssueOptions{Subject: agentSVID, Role: identity.RoleOrchestrator, WorkloadKey: agentKP.Public})
	validator := identity.NewAgentValidator(idpIssuer, idpKP.Public)
	gw50 := x402.NewPaymentGateway(cdp100, cdpKP.Public, validator, "AGENT_CREDIT", "50")

	mc100 := hitlApprovedMint(t, pdp100, cdp100, "payment:AGENT_CREDIT:100")
	agent := x402.NewPayingAgent(mc100, agentToken)
	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if _, err := gw50.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error: credential scope (100) != required amount (50)")
	}
}

func TestPayment_DPoPReplay(t *testing.T) {
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")
	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	agent := x402.NewPayingAgent(mc, agentToken)

	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}

	// First payment: must succeed.
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Second payment with same payload: must be rejected (DPoP jti replay).
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error on DPoP replay — payment must not be charged twice")
	}
}

func TestPayment_AgentTokenMismatch(t *testing.T) {
	pdp, cdp, cdpKP, _, _, _ := setup(t, "AGENT_CREDIT", "50")

	// Issue a second AgentToken for a different agent.
	idpKP2, _ := keys.GenerateECKeyPair()
	agentKP2, _ := keys.GenerateECKeyPair()
	issuer2 := identity.NewAgentIssuer(idpIssuer, idpKP2.Private, time.Hour)
	wrongToken, _ := issuer2.Issue(identity.IssueOptions{
		Subject:     "spiffe://agents.example/agent/impersonator",
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP2.Public,
	})
	validator2 := identity.NewAgentValidator(idpIssuer, idpKP2.Public)
	gw2 := x402.NewPaymentGateway(cdp, cdpKP.Public, validator2, "AGENT_CREDIT", "50")

	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	// Use a credential minted for agentSVID but an AgentToken for a different sub.
	agent := x402.NewPayingAgent(mc, wrongToken)
	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if _, err := gw2.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error: AgentToken sub != CB4A agent_svid")
	}
}

func TestPayment_NonPaymentScope(t *testing.T) {
	// CB4A credential with a non-payment scope should be rejected by the gateway.
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")

	env := &cb4a.EnvelopeClaims{
		AgentSVID: agentSVID,
		Target:    paymentURI,
		Action:    paymentMeth,
		Scope:     "analytics:events:read", // wrong scope for a payment
	}
	decisionJWT, _, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatalf("PDP evaluate: %v", err)
	}
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatalf("CDP mint: %v", err)
	}
	agent := x402.NewPayingAgent(mc, agentToken)
	payload, err := agent.BuildPayload(paymentMeth, paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if _, err := gw.Verify(payload, paymentMeth, paymentURI); err == nil {
		t.Error("expected error: analytics scope is not a payment scope")
	}
}

func TestPayment_WrongHTTPMethod(t *testing.T) {
	// DPoP proof is bound to a specific method; wrong method must fail.
	pdp, cdp, _, gw, agentToken, _ := setup(t, "AGENT_CREDIT", "50")
	mc := autoApprovedMint(t, pdp, cdp, "payment:AGENT_CREDIT:50")
	agent := x402.NewPayingAgent(mc, agentToken)

	// Build proof for GET but gateway verifies as POST.
	payload, err := agent.BuildPayload("GET", paymentURI)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if _, err := gw.Verify(payload, "POST", paymentURI); err == nil {
		t.Error("expected error: DPoP proof htm=GET != POST")
	}
}
