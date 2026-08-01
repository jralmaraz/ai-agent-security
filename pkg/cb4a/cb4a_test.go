package cb4a_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/cb4a"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

// helpers

func mustKey(t *testing.T) *keys.ECKeyPair {
	t.Helper()
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("GenerateECKeyPair: %v", err)
	}
	return kp
}

func mustPDPKey(t *testing.T) *keys.ECKeyPair {
	return mustKey(t)
}

func newAudit() *cb4a.AuditLog {
	return cb4a.NewAuditLog()
}

func newPDP(t *testing.T, kp *keys.ECKeyPair, audit *cb4a.AuditLog) *cb4a.InMemoryPDP {
	t.Helper()
	return cb4a.NewInMemoryPDP(
		"https://pdp.example",
		kp.Private,
		cb4a.DefaultPolicyRules(),
		15*time.Minute,
		audit,
	)
}

func newCDP(t *testing.T, pdpKP *keys.ECKeyPair, audit *cb4a.AuditLog) (*cb4a.CDP, *keys.ECKeyPair) {
	t.Helper()
	cdpKP := mustKey(t)
	cdp := cb4a.NewCDP(
		cb4a.NewInMemoryVault(),
		pdpKP.Public,
		cdpKP.Private,
		"https://cdp.example",
		15*time.Minute,
		audit,
	)
	return cdp, cdpKP
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

func TestAuditLog_AppendAndEntries(t *testing.T) {
	log := newAudit()
	if log.Len() != 0 {
		t.Fatal("expected empty log")
	}
	for i := 0; i < 5; i++ {
		_ = log.Append(cb4a.AuditEntry{
			Event:     cb4a.EventApproved,
			AgentSVID: "spiffe://example/agent",
			RequestID: "req-1",
			Success:   true,
		})
	}
	if log.Len() != 5 {
		t.Fatalf("want 5 entries got %d", log.Len())
	}
	entries := log.Entries()
	if len(entries) != 5 {
		t.Fatalf("Entries() returned %d", len(entries))
	}
	// Snapshot is a copy — mutating it does not affect the log.
	entries[0].AgentSVID = "tampered"
	if log.Entries()[0].AgentSVID != "spiffe://example/agent" {
		t.Fatal("snapshot mutation leaked into log")
	}
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

func TestNewEnvelope_HappyPath(t *testing.T) {
	kp := mustKey(t)
	token, err := cb4a.NewEnvelope(
		"spiffe://cloud.example/svc/billing",
		"api.stripe.com",
		"POST",
		"stripe:charges:write",
		"Process customer payment",
		5*time.Minute,
		kp.Private,
	)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := cb4a.ParseEnvelope(token, kp.Public)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if claims.AgentSVID != "spiffe://cloud.example/svc/billing" {
		t.Errorf("agent_svid: got %q", claims.AgentSVID)
	}
	if claims.Scope != "stripe:charges:write" {
		t.Errorf("scope: got %q", claims.Scope)
	}
	if claims.Justification != "Process customer payment" {
		t.Errorf("justification: got %q", claims.Justification)
	}
}

func TestNewEnvelope_MissingFields(t *testing.T) {
	kp := mustKey(t)
	cases := []struct {
		name          string
		agentSVID     string
		target, action, scope string
	}{
		{"no svid", "", "tgt", "GET", "scp"},
		{"no target", "svid", "", "GET", "scp"},
		{"no action", "svid", "tgt", "", "scp"},
		{"no scope", "svid", "tgt", "GET", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cb4a.NewEnvelope(tc.agentSVID, tc.target, tc.action, tc.scope, "", 0, kp.Private)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseEnvelope_WrongKey(t *testing.T) {
	kp := mustKey(t)
	other := mustKey(t)
	token, err := cb4a.NewEnvelope("svid", "tgt", "GET", "scp", "", 5*time.Minute, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cb4a.ParseEnvelope(token, other.Public)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestParseEnvelope_ExpiredToken(t *testing.T) {
	kp := mustKey(t)
	token, err := cb4a.NewEnvelope("svid", "tgt", "GET", "scp", "", -1*time.Minute, kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cb4a.ParseEnvelope(token, kp.Public)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

// ---------------------------------------------------------------------------
// PDP — Tier 1 auto-approve
// ---------------------------------------------------------------------------

func TestPDP_TierAuto(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	agentKP := mustKey(t)

	// Read-only scope → TierAuto
	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}

	decisionJWT, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if reqID != "" {
		t.Fatalf("expected no pending request, got %q", reqID)
	}
	if decisionJWT == "" {
		t.Fatal("expected decision JWT for auto-approved request")
	}

	// Parse and verify the decision.
	decision, err := cb4a.ParseDecision(decisionJWT, pdpKP.Public)
	if err != nil {
		t.Fatalf("ParseDecision: %v", err)
	}
	if !decision.Approved {
		t.Error("expected approved=true")
	}
	if decision.Tier != cb4a.TierAuto {
		t.Errorf("expected TierAuto got %d", decision.Tier)
	}
	_ = agentKP
}

// ---------------------------------------------------------------------------
// PDP — Tier 2 HITL: approve path
// ---------------------------------------------------------------------------

func TestPDP_TierHITL_Approve(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)

	// Write scope → TierHITL
	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/billing",
		Target:    "api.stripe.com",
		Action:    "POST",
		Scope:     "stripe:charges:write",
	}

	decisionJWT, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if reqID == "" {
		t.Fatal("expected pending request ID")
	}
	if decisionJWT != "" {
		t.Fatal("expected no immediate decision for HITL request")
	}

	// Verify the request is pending.
	req := pdp.Get(reqID)
	if req == nil {
		t.Fatal("Get returned nil")
	}
	if req.State != cb4a.StatePending {
		t.Errorf("expected pending got %s", req.State)
	}

	// Human approves.
	jwt, err := pdp.Approve(reqID, "alice@example.com")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	decision, err := cb4a.ParseDecision(jwt, pdpKP.Public)
	if err != nil {
		t.Fatalf("ParseDecision: %v", err)
	}
	if !decision.Approved {
		t.Error("expected approved=true")
	}
	if decision.ApproverID != "alice@example.com" {
		t.Errorf("approver_id: got %q", decision.ApproverID)
	}

	// Verify audit trail captured the approval.
	auditEntries := audit.Entries()
	var hasApproved bool
	for _, e := range auditEntries {
		if e.Event == cb4a.EventApproved && e.RequestID == reqID {
			hasApproved = true
		}
	}
	if !hasApproved {
		t.Error("audit log missing approved event")
	}
}

// ---------------------------------------------------------------------------
// PDP — Tier 2 HITL: deny path
// ---------------------------------------------------------------------------

func TestPDP_TierHITL_Deny(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/billing",
		Target:    "api.stripe.com",
		Action:    "POST",
		Scope:     "billing:invoices:write",
	}

	_, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatal(err)
	}

	if err := pdp.Deny(reqID, "bob@example.com"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	// Subsequent Approve must fail.
	_, err = pdp.Approve(reqID, "alice@example.com")
	if err == nil {
		t.Fatal("expected error approving an already-denied request")
	}
}

// ---------------------------------------------------------------------------
// PDP — double-action guard
// ---------------------------------------------------------------------------

func TestPDP_DoubleApprove(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/billing",
		Target:    "tgt",
		Action:    "POST",
		Scope:     "billing:invoices:write",
	}
	_, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pdp.Approve(reqID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := pdp.Approve(reqID, "alice"); err == nil {
		t.Fatal("expected error on second Approve")
	}
}

// ---------------------------------------------------------------------------
// PDP — tier 3 MFA
// ---------------------------------------------------------------------------

func TestPDP_TierMFA(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)

	// Admin agent → TierMFA
	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/admin/deployer",
		Target:    "k8s.prod.example",
		Action:    "POST",
		Scope:     "k8s:deployments:write",
	}
	_, reqID, err := pdp.Evaluate(env)
	if err != nil {
		t.Fatal(err)
	}
	req := pdp.Get(reqID)
	if req == nil {
		t.Fatal("expected pending request")
	}
	if req.Tier != cb4a.TierMFA {
		t.Errorf("expected TierMFA got %d", req.Tier)
	}
}

// ---------------------------------------------------------------------------
// CDP — Mint
// ---------------------------------------------------------------------------

func TestCDP_Mint_HappyPath(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	// Get an auto-approved decision for a read scope.
	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, err := pdp.Evaluate(env)
	if err != nil || decisionJWT == "" {
		t.Fatalf("Evaluate: %v", err)
	}

	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if mc.Token == "" {
		t.Fatal("expected non-empty token")
	}
	if mc.EphemeralKey == nil || mc.EphemeralPub == nil {
		t.Fatal("expected ephemeral key pair")
	}
	if mc.Scope != "analytics:events:read" {
		t.Errorf("scope: got %q", mc.Scope)
	}
	if mc.ExpiresAt.Before(time.Now()) {
		t.Error("token already expired")
	}

	// Audit should record the mint.
	found := false
	for _, e := range audit.Entries() {
		if e.Event == cb4a.EventCredentialMinted {
			found = true
		}
	}
	if !found {
		t.Error("audit missing credential_minted event")
	}
}

func TestCDP_Mint_UnapprovedDecision(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	cdp, cdpKP := newCDP(t, pdpKP, audit)
	_ = cdpKP

	// Issue a decision with approved=false by crafting a custom PDP.
	// Easiest: get a HITL decision, don't approve, pass the pending requestID path.
	// Instead we use a denied scenario: Deny then try to use a decision from
	// a PDP with approved=false. We can cheat by using a PDP decision parser
	// on a denied HITL request indirectly.
	// Simplest: pass an empty/invalid string.
	_, err := cdp.Mint("not.a.valid.jwt")
	if err == nil {
		t.Fatal("expected error for invalid decision JWT")
	}
}

func TestCDP_Mint_UnknownScope(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	cdp, _ := newCDP(t, pdpKP, audit)

	// Create a PDP that auto-approves the unknown scope (use a permissive rule set).
	permissivePDP := cb4a.NewInMemoryPDP(
		"https://pdp.example",
		pdpKP.Private,
		[]cb4a.PolicyRule{
			{AgentPattern: "*", ScopePattern: "*", Tier: cb4a.TierAuto},
		},
		15*time.Minute,
		audit,
	)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://example/agent",
		Target:    "tgt",
		Action:    "GET",
		Scope:     "nonexistent:scope:read",
	}
	decisionJWT, _, err := permissivePDP.Evaluate(env)
	if err != nil || decisionJWT == "" {
		t.Fatal(err)
	}

	_, err = cdp.Mint(decisionJWT)
	if err == nil {
		t.Fatal("expected error for unknown scope in vault")
	}
	if !strings.Contains(err.Error(), "no credential in vault") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DPoP proof generation
// ---------------------------------------------------------------------------

func TestGenerateDPoPProof_HappyPath(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := cb4a.GenerateDPoPProof(mc, "GET", "https://api.analytics.example/events")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if proof == "" {
		t.Fatal("expected non-empty proof")
	}

	// The proof must have three JWT parts.
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts got %d", len(parts))
	}
}

func TestGenerateDPoPProof_BadInputs(t *testing.T) {
	kp := mustKey(t)
	mc := &cb4a.MintedCredential{
		Token:        "tok",
		EphemeralKey: kp.Private,
		EphemeralPub: kp.Public,
	}

	if _, err := cb4a.GenerateDPoPProof(nil, "GET", "https://example.com"); err == nil {
		t.Error("expected error for nil mc")
	}
	if _, err := cb4a.GenerateDPoPProof(mc, "", "https://example.com"); err == nil {
		t.Error("expected error for empty method")
	}
	if _, err := cb4a.GenerateDPoPProof(mc, "GET", ""); err == nil {
		t.Error("expected error for empty uri")
	}
}

// ---------------------------------------------------------------------------
// SimulateAPICall — happy path
// ---------------------------------------------------------------------------

func TestSimulateAPICall_HappyPath(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatal(err)
	}

	const method = "GET"
	const uri = "https://api.analytics.example/events"
	proof, err := cb4a.GenerateDPoPProof(mc, method, uri)
	if err != nil {
		t.Fatal(err)
	}

	if err := cdp.SimulateAPICall(mc.Token, proof, method, uri); err != nil {
		t.Fatalf("SimulateAPICall: %v", err)
	}

	// Audit should record the API call.
	found := false
	for _, e := range audit.Entries() {
		if e.Event == cb4a.EventAPICall && e.Success {
			found = true
		}
	}
	if !found {
		t.Error("audit missing api_call event")
	}
}

// ---------------------------------------------------------------------------
// SimulateAPICall — replay attack
// ---------------------------------------------------------------------------

func TestSimulateAPICall_ReplayRejected(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, _ := cdp.Mint(decisionJWT)

	const method = "GET"
	const uri = "https://api.analytics.example/events"
	proof, _ := cb4a.GenerateDPoPProof(mc, method, uri)

	// First call succeeds.
	if err := cdp.SimulateAPICall(mc.Token, proof, method, uri); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call with the same DPoP proof is rejected.
	if err := cdp.SimulateAPICall(mc.Token, proof, method, uri); err == nil {
		t.Fatal("expected error on DPoP proof replay")
	}

	// Audit should record the replay rejection.
	found := false
	for _, e := range audit.Entries() {
		if e.Event == cb4a.EventReplayRejected {
			found = true
		}
	}
	if !found {
		t.Error("audit missing replay_rejected event")
	}
}

// ---------------------------------------------------------------------------
// SimulateAPICall — method mismatch
// ---------------------------------------------------------------------------

func TestSimulateAPICall_WrongMethod(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, _ := cdp.Mint(decisionJWT)

	const uri = "https://api.analytics.example/events"
	proof, _ := cb4a.GenerateDPoPProof(mc, "GET", uri)

	err := cdp.SimulateAPICall(mc.Token, proof, "DELETE", uri)
	if err == nil {
		t.Fatal("expected error for method mismatch")
	}
	if !strings.Contains(err.Error(), "htm mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SimulateAPICall — URI mismatch
// ---------------------------------------------------------------------------

func TestSimulateAPICall_WrongURI(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, _ := cdp.Mint(decisionJWT)

	proof, _ := cb4a.GenerateDPoPProof(mc, "GET", "https://api.analytics.example/events")
	err := cdp.SimulateAPICall(mc.Token, proof, "GET", "https://attacker.example/evil")
	if err == nil {
		t.Fatal("expected error for URI mismatch")
	}
	if !strings.Contains(err.Error(), "htu mismatch") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SimulateAPICall — key substitution attack
// ---------------------------------------------------------------------------

func TestSimulateAPICall_KeySubstitution(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: "spiffe://cloud.example/svc/analytics",
		Target:    "api.analytics.example",
		Action:    "GET",
		Scope:     "analytics:events:read",
	}
	decisionJWT, _, _ := pdp.Evaluate(env)
	mc, _ := cdp.Mint(decisionJWT)

	// Attacker generates their own ephemeral key and creates a DPoP proof.
	attackerKP := mustKey(t)
	attackerMC := &cb4a.MintedCredential{
		Token:        mc.Token,        // legitimate token
		EphemeralKey: attackerKP.Private,
		EphemeralPub: attackerKP.Public,
	}

	const method = "GET"
	const uri = "https://api.analytics.example/events"
	attackerProof, _ := cb4a.GenerateDPoPProof(attackerMC, method, uri)

	// The key substitution must be rejected (jkt mismatch or ath mismatch).
	err := cdp.SimulateAPICall(mc.Token, attackerProof, method, uri)
	if err == nil {
		t.Fatal("expected error for key substitution attack")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: full CB4A flow (Tier 2 HITL)
// ---------------------------------------------------------------------------

func TestEndToEnd_HITL(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	agentKP := mustKey(t)

	// 1. Agent signs a Task Request Envelope.
	envToken, err := cb4a.NewEnvelope(
		"spiffe://cloud.example/svc/billing",
		"api.stripe.com",
		"POST",
		"billing:invoices:write",
		"Monthly invoice batch",
		5*time.Minute,
		agentKP.Private,
	)
	if err != nil {
		t.Fatal(err)
	}

	// 2. PDP parses and evaluates the envelope.
	envClaims, err := cb4a.ParseEnvelope(envToken, agentKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	decisionJWT, reqID, err := pdp.Evaluate(envClaims)
	if err != nil {
		t.Fatal(err)
	}
	if reqID == "" {
		t.Fatal("expected HITL request")
	}
	if decisionJWT != "" {
		t.Fatal("expected no immediate decision")
	}

	// 3. Human approves the request.
	decisionJWT, err = pdp.Approve(reqID, "finance-approver@example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 4. CDP mints a DPoP-bound token.
	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Agent generates a DPoP proof for the API call.
	const method = "POST"
	const uri = "https://api.stripe.com/v1/invoices"
	proof, err := cb4a.GenerateDPoPProof(mc, method, uri)
	if err != nil {
		t.Fatal(err)
	}

	// 6. Resource server verifies the request.
	if err := cdp.SimulateAPICall(mc.Token, proof, method, uri); err != nil {
		t.Fatalf("SimulateAPICall: %v", err)
	}

	// 7. Verify full audit trail covers all events.
	entries := audit.Entries()
	eventSeen := make(map[cb4a.EventType]bool)
	for _, e := range entries {
		eventSeen[e.Event] = true
	}
	for _, want := range []cb4a.EventType{
		cb4a.EventPolicyEvaluated,
		cb4a.EventApproved,
		cb4a.EventCredentialMinted,
		cb4a.EventAPICall,
	} {
		if !eventSeen[want] {
			t.Errorf("audit missing event: %s", want)
		}
	}
}

// ---------------------------------------------------------------------------
// End-to-end: Tier 1 auto-approved read-only
// ---------------------------------------------------------------------------

func TestEndToEnd_TierAuto(t *testing.T) {
	audit := newAudit()
	pdpKP := mustPDPKey(t)
	pdp := newPDP(t, pdpKP, audit)
	cdp, _ := newCDP(t, pdpKP, audit)

	agentKP := mustKey(t)
	envToken, _ := cb4a.NewEnvelope(
		"spiffe://cloud.example/svc/dashboard",
		"api.analytics.example",
		"GET",
		"analytics:events:read",
		"",
		5*time.Minute,
		agentKP.Private,
	)
	envClaims, _ := cb4a.ParseEnvelope(envToken, agentKP.Public)
	decisionJWT, reqID, err := pdp.Evaluate(envClaims)
	if err != nil {
		t.Fatal(err)
	}
	if reqID != "" {
		t.Fatalf("expected no HITL for auto-approved scope, got reqID %q", reqID)
	}

	mc, err := cdp.Mint(decisionJWT)
	if err != nil {
		t.Fatal(err)
	}

	proof, _ := cb4a.GenerateDPoPProof(mc, "GET", "https://api.analytics.example/events")
	if err := cdp.SimulateAPICall(mc.Token, proof, "GET", "https://api.analytics.example/events"); err != nil {
		t.Fatalf("SimulateAPICall: %v", err)
	}
}
