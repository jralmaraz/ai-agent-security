//go:build js && wasm

// Command demo-wasm compiles to WebAssembly and exports agent fabric functions
// to the browser demo, making the identity chain lifecycle interactive.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/jralmaraz/ai-agent-security/pkg/cb4a"
	"github.com/jralmaraz/ai-agent-security/pkg/federation"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/jralmaraz/ai-agent-security/pkg/keys"
	"github.com/jralmaraz/ai-agent-security/pkg/obo"
	x402pkg "github.com/jralmaraz/ai-agent-security/pkg/x402"
)

// ── global demo state ─────────────────────────────────────────────────────────

var (
	idpPriv   *ecdsa.PrivateKey
	idpPub    *ecdsa.PublicKey
	issuer    *identity.AgentIssuer
	validator *identity.AgentValidator
	pv        *identity.ProofValidator

	orchestratorPriv *ecdsa.PrivateKey
	orchestratorPub  *ecdsa.PublicKey
	executorPriv     *ecdsa.PrivateKey
	executorPub      *ecdsa.PublicKey

	orchestratorToken string
	executorToken     string
	chain             identity.AgentChain
)

// ── exported functions ────────────────────────────────────────────────────────

func setup(_ js.Value, _ []js.Value) any {
	var err error
	idpPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate IdP key: " + err.Error())
	}
	idpPub = &idpPriv.PublicKey

	orchestratorPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate orchestrator key: " + err.Error())
	}
	orchestratorPub = &orchestratorPriv.PublicKey

	executorPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate executor key: " + err.Error())
	}
	executorPub = &executorPriv.PublicKey

	issuer = identity.NewAgentIssuer("https://idp.agent-fabric.example", idpPriv, time.Hour)
	validator = identity.NewAgentValidator("https://idp.agent-fabric.example", idpPub)
	pv = identity.NewProofValidator()

	return okObj(map[string]any{
		"message": "Keys generated. IdP and agent key pairs ready.",
	})
}

func issueOrchestratorToken(_ js.Value, _ []js.Value) any {
	if issuer == nil {
		return errObj("call setup() first")
	}
	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://agent-fabric.example/orchestrator",
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: orchestratorPub,
	})
	if err != nil {
		return errObj("issue orchestrator token: " + err.Error())
	}
	orchestratorToken = tok
	chain = identity.AgentChain{tok}

	return okObj(map[string]any{
		"token":      truncate(tok),
		"fullToken":  tok,
		"chain":      chain.String(),
		"chainHash":  chain.Hash(),
		"chainDepth": 0,
		"role":       identity.RoleOrchestrator,
	})
}

func delegateToExecutor(_ js.Value, _ []js.Value) any {
	if orchestratorToken == "" {
		return errObj("issue orchestrator token first")
	}
	if issuer == nil {
		return errObj("call setup() first")
	}

	tok, err := issuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://agent-fabric.example/executor",
		Role:        identity.RoleExecutor,
		ChainDepth:  1,
		WorkloadKey: executorPub,
	})
	if err != nil {
		return errObj("issue executor token: " + err.Error())
	}
	executorToken = tok
	extended, err := chain.Extend(tok)
	if err != nil {
		return errObj("extend chain: " + err.Error())
	}
	chain = extended

	return okObj(map[string]any{
		"token":      truncate(tok),
		"fullToken":  tok,
		"chainLen":   chain.Len(),
		"chainHash":  chain.Hash(),
		"chainDepth": 1,
		"role":       identity.RoleExecutor,
	})
}

func validateChain(_ js.Value, _ []js.Value) any {
	if validator == nil {
		return errObj("call setup() first")
	}
	if chain.Len() == 0 {
		return errObj("build a chain first")
	}

	validators := map[string]*identity.AgentValidator{
		"https://idp.agent-fabric.example": validator,
	}
	results, err := chain.Validate(validators)
	if err != nil {
		return errObj("chain validation failed: " + err.Error())
	}

	summaries := make([]map[string]any, len(results))
	for i, r := range results {
		summaries[i] = map[string]any{
			"subject":    r.Claims.Subject,
			"role":       r.Claims.Role,
			"chainDepth": r.Claims.ChainDepth,
		}
	}
	out, _ := json.Marshal(summaries)
	return okObj(map[string]any{
		"hops":    len(results),
		"details": string(out),
	})
}

func generateProof(_ js.Value, args []js.Value) any {
	if pv == nil {
		return errObj("call setup() first")
	}
	if chain.Len() == 0 {
		return errObj("build a chain first")
	}

	targetURI := "https://tool-server.example/api/weather"
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		targetURI = args[0].String()
	}

	signerKey := executorPriv
	if executorToken == "" {
		signerKey = orchestratorPriv
	}

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   targetURI,
		Chain:       chain,
		WorkloadKey: signerKey,
	})
	if err != nil {
		return errObj("generate proof: " + err.Error())
	}

	return okObj(map[string]any{
		"proof":     truncate(proof),
		"fullProof": proof,
		"targetURI": targetURI,
		"chainHash": chain.Hash(),
	})
}

func simulateReplayAttack(_ js.Value, args []js.Value) any {
	if pv == nil {
		return errObj("call setup() first")
	}
	if chain.Len() == 0 {
		return errObj("build a chain first")
	}

	targetURI := "https://tool-server.example/api/data"
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		targetURI = args[0].String()
	}

	signerKey := orchestratorPriv
	signerPub := orchestratorPub
	if executorToken != "" {
		signerKey = executorPriv
		signerPub = executorPub
	}

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   targetURI,
		Chain:       chain,
		WorkloadKey: signerKey,
	})
	if err != nil {
		return errObj("generate proof: " + err.Error())
	}

	vopts := identity.ProofValidateOptions{
		ProofToken:  proof,
		Chain:       chain,
		RequestURI:  targetURI,
		WorkloadKey: signerPub,
		CheckReplay: true,
	}

	// First use — should succeed.
	if _, err := pv.Validate(vopts); err != nil {
		return errObj("first validation unexpectedly failed: " + err.Error())
	}

	// Second use — should be rejected.
	_, replayErr := pv.Validate(vopts)
	if replayErr == nil {
		return errObj("replay was NOT detected — this is a bug!")
	}

	return okObj(map[string]any{
		"firstAttempt":  "ACCEPTED",
		"secondAttempt": "REJECTED: " + replayErr.Error(),
		"protection":    "jti replay detection working correctly",
	})
}

func simulateTampering(_ js.Value, _ []js.Value) any {
	if validator == nil {
		return errObj("call setup() first")
	}
	if orchestratorToken == "" {
		return errObj("issue orchestrator token first")
	}

	// Replace the signature part with zeros.
	parts := splitJWT(orchestratorToken)
	if len(parts) != 3 {
		return errObj("malformed token")
	}
	tampered := parts[0] + "." + parts[1] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err := validator.Validate(tampered)
	if err == nil {
		return errObj("tampered token was accepted — this is a bug!")
	}

	return okObj(map[string]any{
		"tamperedToken": truncate(tampered),
		"result":        "REJECTED: " + err.Error(),
		"protection":    "ES256 signature verification working correctly",
	})
}

// ── CB4A (Credential Broker for Agents) state ─────────────────────────────────

var (
	globalPDP    *cb4a.InMemoryPDP
	globalCDP    *cb4a.CDP
	globalAudit  *cb4a.AuditLog
	globalPDPKP  *keys.ECKeyPair
	globalMinted *cb4a.MintedCredential // most recently minted credential
)

// cb4aInit initialises the PDP, CDP, and audit log for the live demo.
func cb4aInit(_ js.Value, _ []js.Value) any {
	var err error
	globalPDPKP, err = keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate PDP key: " + err.Error())
	}
	cdpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate CDP key: " + err.Error())
	}

	globalAudit = cb4a.NewAuditLog()
	globalPDP = cb4a.NewInMemoryPDP(
		"https://pdp.demo.example",
		globalPDPKP.Private,
		cb4a.DefaultPolicyRules(),
		15*time.Minute,
		globalAudit,
	)
	globalCDP = cb4a.NewCDP(
		cb4a.NewInMemoryVault(),
		globalPDPKP.Public,
		cdpKP.Private,
		"https://cdp.demo.example",
		15*time.Minute,
		globalAudit,
	)
	globalMinted = nil

	pdpJWK, _ := keys.PublicKeyToJWK(globalPDPKP.Public, "pdp-key")
	pdpKeyX := ""
	if pdpJWK != nil {
		pdpKeyX = pdpJWK.X
	}

	return okObj(map[string]any{
		"message":  "CB4A demo initialised. PDP, CDP, and vault ready.",
		"pdpKeyX":  pdpKeyX,
		"vaultSize": 5,
	})
}

// cb4aSubmit submits a credential request to the PDP.
// args: [agentSVID, scope, target, action, justification?]
func cb4aSubmit(_ js.Value, args []js.Value) any {
	if globalPDP == nil {
		return errObj("call cb4aInit() first")
	}
	if len(args) < 4 {
		return errObj("usage: cb4aSubmit(svid, scope, target, action [, justification])")
	}
	agentSVID := args[0].String()
	scope := args[1].String()
	target := args[2].String()
	action := args[3].String()
	justification := ""
	if len(args) > 4 {
		justification = args[4].String()
	}

	env := &cb4a.EnvelopeClaims{
		AgentSVID:     agentSVID,
		Target:        target,
		Action:        action,
		Scope:         scope,
		Justification: justification,
	}
	_ = globalAudit.Append(cb4a.AuditEntry{
		Event:     cb4a.EventEnvelopeReceived,
		AgentSVID: agentSVID,
		Target:    target,
		Action:    action,
		Scope:     scope,
		Detail:    "TRE submitted to PDP",
		Success:   true,
	})

	decisionJWT, reqID, err := globalPDP.Evaluate(env)
	if err != nil {
		return errObj("PDP evaluate: " + err.Error())
	}

	tierNames := map[cb4a.ApprovalTier]string{
		cb4a.TierAuto: "Tier 1 — Auto-Approved",
		cb4a.TierHITL: "Tier 2 — Human-in-the-Loop",
		cb4a.TierMFA:  "Tier 3 — MFA Required",
	}

	if decisionJWT != "" {
		return okObj(map[string]any{
			"tier":        int(cb4a.TierAuto),
			"tierName":    tierNames[cb4a.TierAuto],
			"status":      "auto-approved",
			"decisionJWT": decisionJWT,
		})
	}

	req := globalPDP.Get(reqID)
	tier := cb4a.TierHITL
	if req != nil {
		tier = req.Tier
	}
	return okObj(map[string]any{
		"tier":      int(tier),
		"tierName":  tierNames[tier],
		"status":    "pending",
		"requestID": reqID,
	})
}

// cb4aApprove approves a pending HITL/MFA request.
// args: [requestID]
func cb4aApprove(_ js.Value, args []js.Value) any {
	if globalPDP == nil {
		return errObj("call cb4aInit() first")
	}
	if len(args) < 1 {
		return errObj("usage: cb4aApprove(requestID)")
	}
	reqID := args[0].String()
	decisionJWT, err := globalPDP.Approve(reqID, "demo-approver")
	if err != nil {
		return errObj("approve: " + err.Error())
	}
	return okObj(map[string]any{
		"decisionJWT": decisionJWT,
		"approver":    "demo-approver",
	})
}

// cb4aDeny denies a pending HITL/MFA request.
// args: [requestID]
func cb4aDeny(_ js.Value, args []js.Value) any {
	if globalPDP == nil {
		return errObj("call cb4aInit() first")
	}
	if len(args) < 1 {
		return errObj("usage: cb4aDeny(requestID)")
	}
	reqID := args[0].String()
	if err := globalPDP.Deny(reqID, "demo-approver"); err != nil {
		return errObj("deny: " + err.Error())
	}
	return okObj(map[string]any{"denied": true, "requestID": reqID})
}

// cb4aMint mints a DPoP-bound access token from a signed PDP decision.
// args: [decisionJWT]
func cb4aMint(_ js.Value, args []js.Value) any {
	if globalCDP == nil {
		return errObj("call cb4aInit() first")
	}
	if len(args) < 1 {
		return errObj("usage: cb4aMint(decisionJWT)")
	}
	decisionJWT := args[0].String()
	mc, err := globalCDP.Mint(decisionJWT)
	if err != nil {
		return errObj("mint: " + err.Error())
	}
	globalMinted = mc

	// Derive a short key fingerprint for display (no secret data exposed).
	ephJWK, _ := keys.PublicKeyToJWK(mc.EphemeralPub, "")
	keyFingerprint := "(key error)"
	if ephJWK != nil && len(ephJWK.X) >= 8 {
		keyFingerprint = ephJWK.X[:8] + "..."
	}

	return okObj(map[string]any{
		"scope":          mc.Scope,
		"expiresAt":      mc.ExpiresAt.Format(time.RFC3339),
		"tokenPreview":   truncate(mc.Token),
		"ephKeyFingerprint": keyFingerprint,
		"dpopBound":      true,
	})
}

// cb4aAPICall simulates an agent making a DPoP-bound API call.
// args: [method, uri]
func cb4aAPICall(_ js.Value, args []js.Value) any {
	if globalCDP == nil {
		return errObj("call cb4aInit() first")
	}
	if globalMinted == nil {
		return errObj("call cb4aMint() first")
	}
	if len(args) < 2 {
		return errObj("usage: cb4aAPICall(method, uri)")
	}
	method := args[0].String()
	uri := args[1].String()

	proof, err := cb4a.GenerateDPoPProof(globalMinted, method, uri)
	if err != nil {
		return errObj("generate DPoP proof: " + err.Error())
	}
	if err := globalCDP.SimulateAPICall(globalMinted.Token, proof, method, uri); err != nil {
		return map[string]any{
			"ok":     false,
			"detail": "REJECTED: " + err.Error(),
		}
	}
	return okObj(map[string]any{
		"detail":    fmt.Sprintf("%s %s — authorized", method, uri),
		"dpopProof": truncate(proof),
	})
}

// cb4aAudit returns the full audit trail as a JSON string.
func cb4aAudit(_ js.Value, _ []js.Value) any {
	if globalAudit == nil {
		return errObj("call cb4aInit() first")
	}
	entries := globalAudit.Entries()
	type auditRow struct {
		Event     string `json:"event"`
		AgentSVID string `json:"agent_svid"`
		Scope     string `json:"scope"`
		Tier      int    `json:"tier,omitempty"`
		RequestID string `json:"request_id,omitempty"`
		Detail    string `json:"detail,omitempty"`
		Success   bool   `json:"success"`
		Timestamp string `json:"timestamp"`
	}
	rows := make([]auditRow, len(entries))
	for i, e := range entries {
		rows[i] = auditRow{
			Event:     string(e.Event),
			AgentSVID: e.AgentSVID,
			Scope:     e.Scope,
			Tier:      e.Tier,
			RequestID: e.RequestID,
			Detail:    e.Detail,
			Success:   e.Success,
			Timestamp: e.Timestamp.Format("15:04:05.000"),
		}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return errObj("marshal audit: " + err.Error())
	}
	return okObj(map[string]any{"entries": string(b), "count": len(rows)})
}

// ── x402 payment demo state ───────────────────────────────────────────────────

const (
	x402IdpIssuer  = "https://idp.x402-demo.example"
	x402AgentSVID  = "spiffe://x402-demo.example/agent/payment-bot"
	x402PaymentURI = "https://api.vendor.example/v1/premium-data"
)

var (
	x402IDP       *identity.AgentIssuer
	x402Validator *identity.AgentValidator
	x402PDP       *cb4a.InMemoryPDP
	x402CDP       *cb4a.CDP
	x402CDPPub    *ecdsa.PublicKey
	x402GW        *x402pkg.PaymentGateway
	x402AuditLog  *cb4a.AuditLog
	x402AgentTok  string
	x402Minted    *cb4a.MintedCredential
	x402PendReqID string
	x402DecJWT    string
)

// x402Init initialises the full x402 demo stack.
func x402Init(_ js.Value, _ []js.Value) any {
	// IdP key pair
	idpKP, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate IdP key: " + err.Error())
	}
	// Agent key pair
	agentKP, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate agent key: " + err.Error())
	}
	// PDP key pair
	pdpKP, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate PDP key: " + err.Error())
	}
	// CDP key pair
	cdpKP, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate CDP key: " + err.Error())
	}

	x402AuditLog = cb4a.NewAuditLog()
	x402PDP = cb4a.NewInMemoryPDP(
		"https://pdp.x402-demo.example",
		pdpKP,
		cb4a.DefaultPolicyRules(),
		15*time.Minute,
		x402AuditLog,
	)
	x402CDP = cb4a.NewCDP(
		cb4a.NewInMemoryVault(),
		&pdpKP.PublicKey,
		cdpKP,
		"https://cdp.x402-demo.example",
		15*time.Minute,
		x402AuditLog,
	)
	x402CDPPub = &cdpKP.PublicKey

	x402IDP = identity.NewAgentIssuer(x402IdpIssuer, idpKP, time.Hour)
	x402Validator = identity.NewAgentValidator(x402IdpIssuer, &idpKP.PublicKey)

	// Issue AgentToken for the demo paying agent
	tok, err := x402IDP.Issue(identity.IssueOptions{
		Subject:     x402AgentSVID,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: &agentKP.PublicKey,
	})
	if err != nil {
		return errObj("issue AgentToken: " + err.Error())
	}
	x402AgentTok = tok
	x402Minted = nil
	x402PendReqID = ""
	x402DecJWT = ""

	// PaymentGateway — configured for 50 AGENT_CREDIT (auto-approve tier)
	x402GW = x402pkg.NewPaymentGateway(x402CDP, x402CDPPub, x402Validator, "AGENT_CREDIT", "50")

	return okObj(map[string]any{
		"message":    "x402 demo initialised. PDP, CDP, PaymentGateway, and AgentToken ready.",
		"agentSVID":  x402AgentSVID,
		"agentToken": truncate(tok),
	})
}

// x402HitAPI simulates an agent calling an x402-protected endpoint.
// Returns the 402 PaymentRequired payload that the server would send.
func x402HitAPI(_ js.Value, args []js.Value) any {
	if x402GW == nil {
		return errObj("call x402Init() first")
	}
	uri := x402PaymentURI
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		uri = args[0].String()
	}
	pr := x402GW.Require(uri)
	b, _ := json.Marshal(pr)
	return okObj(map[string]any{
		"status":          402,
		"message":         "HTTP 402 Payment Required",
		"paymentRequired": string(b),
		"resource":        uri,
		"asset":           pr.Accepts[0].Asset,
		"amount":          pr.Accepts[0].Amount,
		"scheme":          pr.Accepts[0].Scheme,
	})
}

// x402RequestSpending submits a CB4A credential request for a payment scope.
// args[0] = amount string (e.g. "50" for auto-approve, "100" for HITL)
func x402RequestSpending(_ js.Value, args []js.Value) any {
	if x402PDP == nil {
		return errObj("call x402Init() first")
	}
	amount := "50"
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		amount = args[0].String()
	}
	scope := "payment:AGENT_CREDIT:" + amount

	// Update gateway for the requested amount
	x402GW = x402pkg.NewPaymentGateway(x402CDP, x402CDPPub, x402Validator, "AGENT_CREDIT", amount)

	env := &cb4a.EnvelopeClaims{
		AgentSVID: x402AgentSVID,
		Target:    x402PaymentURI,
		Action:    "GET",
		Scope:     scope,
	}
	decisionJWT, reqID, err := x402PDP.Evaluate(env)
	if err != nil {
		return errObj("PDP evaluate: " + err.Error())
	}

	tierNames := map[cb4a.ApprovalTier]string{
		cb4a.TierAuto: "Tier 1 — Auto-Approved",
		cb4a.TierHITL: "Tier 2 — Human-in-the-Loop",
		cb4a.TierMFA:  "Tier 3 — MFA Required",
	}

	if decisionJWT != "" {
		x402DecJWT = decisionJWT
		x402PendReqID = ""
		return okObj(map[string]any{
			"tier":     int(cb4a.TierAuto),
			"tierName": tierNames[cb4a.TierAuto],
			"status":   "auto-approved",
			"scope":    scope,
		})
	}

	x402PendReqID = reqID
	x402DecJWT = ""
	req := x402PDP.Get(reqID)
	tier := cb4a.TierHITL
	if req != nil {
		tier = req.Tier
	}
	return okObj(map[string]any{
		"tier":      int(tier),
		"tierName":  tierNames[tier],
		"status":    "pending",
		"requestID": reqID,
		"scope":     scope,
	})
}

// x402Approve approves a pending HITL payment request.
// args[0] = requestID (from x402RequestSpending response)
func x402Approve(_ js.Value, args []js.Value) any {
	if x402PDP == nil {
		return errObj("call x402Init() first")
	}
	reqID := x402PendReqID
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		reqID = args[0].String()
	}
	if reqID == "" {
		return errObj("no pending request to approve")
	}
	dec, err := x402PDP.Approve(reqID, "finance-approver")
	if err != nil {
		return errObj("approve: " + err.Error())
	}
	x402DecJWT = dec
	x402PendReqID = ""
	return okObj(map[string]any{
		"approved":  true,
		"approver":  "finance-approver",
		"requestID": reqID,
	})
}

// x402MintCred mints a DPoP-bound payment credential from the approved PDP decision.
func x402MintCred(_ js.Value, _ []js.Value) any {
	if x402CDP == nil {
		return errObj("call x402Init() first")
	}
	if x402DecJWT == "" {
		return errObj("no approved decision — call x402RequestSpending or x402Approve first")
	}
	mc, err := x402CDP.Mint(x402DecJWT)
	if err != nil {
		return errObj("CDP mint: " + err.Error())
	}
	x402Minted = mc
	x402DecJWT = ""

	ephJWK, _ := keys.PublicKeyToJWK(mc.EphemeralPub, "")
	keyFP := "(key error)"
	if ephJWK != nil && len(ephJWK.X) >= 8 {
		keyFP = ephJWK.X[:8] + "…"
	}
	return okObj(map[string]any{
		"scope":             mc.Scope,
		"expiresAt":         mc.ExpiresAt.Format(time.RFC3339),
		"tokenPreview":      truncate(mc.Token),
		"ephKeyFingerprint": keyFP,
		"dpopBound":         true,
		"message":           "Payment credential minted. DPoP-bound to ephemeral key — no replay possible.",
	})
}

// x402Pay builds a payment payload and verifies it through the PaymentGateway.
// args[0] = HTTP method (default "GET"), args[1] = URI (default x402PaymentURI)
func x402Pay(_ js.Value, args []js.Value) any {
	if x402GW == nil {
		return errObj("call x402Init() first")
	}
	if x402Minted == nil {
		return errObj("call x402MintCred() first")
	}
	if x402AgentTok == "" {
		return errObj("call x402Init() first (AgentToken missing)")
	}
	method := "GET"
	uri := x402PaymentURI
	if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
		method = args[0].String()
	}
	if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
		uri = args[1].String()
	}

	agent := x402pkg.NewPayingAgent(x402Minted, x402AgentTok)
	payload, err := agent.BuildPayload(method, uri)
	if err != nil {
		return errObj("build payment payload: " + err.Error())
	}

	result, err := x402GW.Verify(payload, method, uri)
	if err != nil {
		return map[string]any{
			"ok":     false,
			"detail": "REJECTED: " + err.Error(),
		}
	}
	return okObj(map[string]any{
		"agentSVID": result.AgentSVID,
		"asset":     result.Asset,
		"amount":    result.Amount,
		"scope":     result.Scope,
		"resource":  result.Resource,
		"status":    "200 OK",
		"message":   "Payment authorized — access granted. DPoP proof consumed (no replay).",
	})
}

// x402GetAudit returns the x402 payment audit trail.
func x402GetAudit(_ js.Value, _ []js.Value) any {
	if x402AuditLog == nil {
		return errObj("call x402Init() first")
	}
	entries := x402AuditLog.Entries()
	type auditRow struct {
		Event     string `json:"event"`
		AgentSVID string `json:"agent_svid"`
		Scope     string `json:"scope"`
		Tier      int    `json:"tier,omitempty"`
		RequestID string `json:"request_id,omitempty"`
		Detail    string `json:"detail,omitempty"`
		Success   bool   `json:"success"`
		Timestamp string `json:"timestamp"`
	}
	rows := make([]auditRow, len(entries))
	for i, e := range entries {
		rows[i] = auditRow{
			Event:     string(e.Event),
			AgentSVID: e.AgentSVID,
			Scope:     e.Scope,
			Tier:      e.Tier,
			RequestID: e.RequestID,
			Detail:    e.Detail,
			Success:   e.Success,
			Timestamp: e.Timestamp.Format("15:04:05.000"),
		}
	}
	b, err := json.Marshal(rows)
	if err != nil {
		return errObj("marshal audit: " + err.Error())
	}
	return okObj(map[string]any{"entries": string(b), "count": len(rows)})
}

// ── Federation (OID-FED) state ────────────────────────────────────────────────

var (
	fedAnchorPriv  *ecdsa.PrivateKey
	fedAnchorPub   *ecdsa.PublicKey
	fedOrgBPriv    *ecdsa.PrivateKey
	fedOrgBPub     *ecdsa.PublicKey
	fedOrgBIssuer  *identity.AgentIssuer
	fedOrgBEC      string // Entity Configuration JWT
	fedOrgBSS      string // Subordinate Statement JWT
	fedOrgBToken   string // Agent token issued by Org-B IdP
	fedResolver    *federation.InMemoryResolver
)

const (
	fedAnchorID = "https://trust-anchor.enterprise.example"
	fedOrgBID   = "https://idp.org-b.example"
	fedOrgBSub  = "spiffe://org-b.example/agent/data-collector"
)

// setupFederation creates a complete OID-FED trust chain for a cross-org agent.
func setupFederation(_ js.Value, _ []js.Value) any {
	var err error

	fedAnchorPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate anchor key: " + err.Error())
	}
	fedAnchorPub = &fedAnchorPriv.PublicKey

	fedOrgBPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errObj("generate Org-B IdP key: " + err.Error())
	}
	fedOrgBPub = &fedOrgBPriv.PublicKey

	fedOrgBEC, err = federation.BuildEntityConfiguration(
		fedOrgBID, fedOrgBPriv, "orgb-key",
		"Org B Agent Platform",
		[]string{fedAnchorID},
		24*time.Hour,
	)
	if err != nil {
		return errObj("build entity configuration: " + err.Error())
	}

	fedOrgBSS, err = federation.BuildSubordinateStatement(
		fedAnchorID, fedOrgBID,
		fedOrgBPub, "orgb-key",
		fedAnchorPriv, "anchor-key",
		24*time.Hour,
	)
	if err != nil {
		return errObj("build subordinate statement: " + err.Error())
	}

	fedOrgBIssuer = identity.NewAgentIssuer(fedOrgBID, fedOrgBPriv, time.Hour)

	fedResolver = federation.NewInMemoryResolver(map[string]*ecdsa.PublicKey{
		fedAnchorID: fedAnchorPub,
	})
	fedResolver.RegisterEntityConfig(fedOrgBID, fedOrgBEC)
	fedResolver.RegisterSubordinateStatement(fedOrgBID, fedOrgBSS)

	// PublicKeyToJWK returns a struct pointer — must extract primitive fields
	// before putting into the return map; js.ValueOf panics on struct pointers.
	anchorJWK, err := keys.PublicKeyToJWK(fedAnchorPub, "anchor-key")
	if err != nil {
		return errObj("anchor JWK: " + err.Error())
	}
	orgBJWK, err := keys.PublicKeyToJWK(fedOrgBPub, "orgb-key")
	if err != nil {
		return errObj("orgB JWK: " + err.Error())
	}

	ec, _ := federation.ParseEntityConfiguration(fedOrgBEC)
	ss, _ := federation.ParseSubordinateStatement(fedOrgBSS)

	// Build ecHints as []interface{} — js.ValueOf cannot convert []string.
	var ecIss, ssSub string
	var ecHints []interface{}
	if ec != nil {
		ecIss = ec.Issuer
		for _, h := range ec.AuthorityHints {
			ecHints = append(ecHints, h)
		}
	}
	if ss != nil {
		ssSub = ss.Subject
	}

	return okObj(map[string]any{
		"anchorID":   fedAnchorID,
		"orgBID":     fedOrgBID,
		"ecJWT":      fedOrgBEC,
		"ecIss":      ecIss,
		"ecHints":    ecHints,
		"ssSub":      ssSub,
		"anchorKeyX": anchorJWK.X,
		"orgBKeyX":   orgBJWK.X,
	})
}

// issueOrgBAgentToken issues an AgentToken using Org-B's federated IdP.
func issueOrgBAgentToken(_ js.Value, _ []js.Value) any {
	if fedOrgBIssuer == nil {
		return errObj("call setupFederation() first")
	}

	workloadKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate workload key: " + err.Error())
	}

	fedOrgBToken, err = fedOrgBIssuer.Issue(identity.IssueOptions{
		Subject:     fedOrgBSub,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: workloadKP.Public,
	})
	if err != nil {
		return errObj("issue Org-B token: " + err.Error())
	}

	return okObj(map[string]any{
		"token":   fedOrgBToken,
		"issuer":  fedOrgBID,
		"subject": fedOrgBSub,
	})
}

// validateFederatedToken simulates the gateway resolving an unknown issuer via OID-FED.
func validateFederatedToken(_ js.Value, _ []js.Value) any {
	if fedResolver == nil {
		return errObj("call setupFederation() first")
	}
	if fedOrgBToken == "" {
		return errObj("call issueOrgBAgentToken() first")
	}

	// Peek at the issuer (no static config for Org-B).
	entity, err := fedResolver.Resolve(context.Background(), fedOrgBID)
	if err != nil {
		return errObj("federation resolve: " + err.Error())
	}
	resolvedPub, err := entity.PublicKey()
	if err != nil {
		return errObj("extract resolved key: " + err.Error())
	}

	// Validate with the dynamically-resolved key.
	dynValidator := identity.NewAgentValidator(fedOrgBID, resolvedPub)
	va, err := dynValidator.Validate(fedOrgBToken)
	if err != nil {
		return errObj("validate federated token: " + err.Error())
	}

	orgBJWK, _ := keys.PublicKeyToJWK(resolvedPub, "orgb-key")
	var resolvedKeyX string
	if orgBJWK != nil {
		resolvedKeyX = orgBJWK.X
	}

	return okObj(map[string]any{
		"subject":          va.Claims.Subject,
		"issuer":           va.Claims.Issuer,
		"resolvedViaChain": true,
		"trustAnchor":      fedAnchorID,
		"resolvedKeyX":     resolvedKeyX,
	})
}

// simulateMTLSBinding demonstrates the token-cert binding property.
// It generates a CA, issues agent certs, and simulates the gateway's
// verifyMTLSBinding check for both the happy path and a stolen-token attack.
// Returns only primitive/string values safe for js.ValueOf.
func simulateMTLSBinding(_ js.Value, _ []js.Value) any {
	if issuer == nil {
		return errObj("call setup() first")
	}

	// Generate an ephemeral CA for this trust domain.
	ca, err := keys.GenerateCA("agents.example")
	if err != nil {
		return errObj("generate CA: " + err.Error())
	}

	// Legitimate agent: one key pair serves as cert key, cnf.jwk, and proof key.
	const legitSub = "spiffe://agents.example/agent/orchestrator"
	legitKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate legit key: " + err.Error())
	}
	legitCert, err := ca.IssueAgentCert(legitSub, legitKP.Public, nil)
	if err != nil {
		return errObj("issue legit cert: " + err.Error())
	}
	// Issue token with sub matching the cert URI SAN.
	legitTok, err := issuer.Issue(identity.IssueOptions{
		Subject:     legitSub,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: legitKP.Public,
	})
	if err != nil {
		return errObj("issue legit token: " + err.Error())
	}
	// Peek subject from token (for display).
	va, err := validator.Validate(legitTok)
	legitTokenSub := "unknown"
	if err == nil {
		legitTokenSub = va.Claims.Subject
	}
	// Binding check: cert URI SAN[0] == token sub.
	legitSAN := ""
	if len(legitCert.Cert.URIs) > 0 {
		legitSAN = legitCert.Cert.URIs[0].String()
	}
	legitMatch := legitSAN == legitTokenSub
	legitResult := "REJECTED"
	if legitMatch {
		legitResult = "ALLOWED"
	}

	// Attacker: has their own cert but uses the legit token (stolen).
	const attackerSub = "spiffe://agents.example/agent/attacker"
	attackerKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate attacker key: " + err.Error())
	}
	attackerCert, err := ca.IssueAgentCert(attackerSub, attackerKP.Public, nil)
	if err != nil {
		return errObj("issue attacker cert: " + err.Error())
	}
	attackerSAN := ""
	if len(attackerCert.Cert.URIs) > 0 {
		attackerSAN = attackerCert.Cert.URIs[0].String()
	}
	// Attacker presents their cert but the stolen token sub is legitSub.
	attackMatch := attackerSAN == legitTokenSub
	attackResult := fmt.Sprintf(
		"REJECTED: cert SAN %q != token sub %q", attackerSAN, legitTokenSub)
	if attackMatch {
		attackResult = "ALLOWED (bug if true)"
	}

	return okObj(map[string]any{
		// CA
		"trustDomain": "agents.example",
		// Legit agent
		"legitSAN":    legitSAN,
		"legitSub":    legitTokenSub,
		"legitMatch":  legitMatch,
		"legitResult": legitResult,
		// Attacker (stolen token)
		"attackerSAN": attackerSAN,
		"stolenSub":   legitTokenSub,
		"attackMatch": attackMatch,
		"attackResult": attackResult,
	})
}

// simulateCredentialBroker generates a real WIMSE AgentToken + AgentProofToken
// and a simulated CB4A Task Request Envelope for the same agent identity,
// illustrating how draft-hartman-credential-broker-4-agents-00 and WIMSE Agent
// Fabric represent the same agent action from complementary angles.
func simulateCredentialBroker(_ js.Value, _ []js.Value) any {
	if issuer == nil {
		return errObj("call setup() first")
	}

	const (
		agentSub    = "spiffe://enterprise.example/agent/billing-agent"
		wimseTarget = "https://tool-server.example/api/billing"
	)

	agentKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate agent key: " + err.Error())
	}

	// WIMSE: AgentToken with cnf.jwk binding + AgentProofToken per-request proof.
	wTok, err := issuer.Issue(identity.IssueOptions{
		Subject:     agentSub,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		return errObj("issue WIMSE token: " + err.Error())
	}
	wChain := identity.AgentChain{wTok}
	wProof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   wimseTarget,
		Chain:       wChain,
		WorkloadKey: agentKP.Private,
	})
	if err != nil {
		return errObj("generate WIMSE proof: " + err.Error())
	}
	chainHash := wChain.Hash()

	// CB4A: simulate a Task Request Envelope — the auditable request artifact
	// submitted to the Policy Decision Point before credential issuance.
	envelope := map[string]interface{}{
		"request_id":    "req-" + chainHash[:12],
		"agent_svid":    agentSub,
		"target":        "https://billing-api.vendor.example/v2/invoices",
		"action":        "read",
		"scope":         "billing:invoices:read",
		"justification": "Monthly report (evidence only, excluded from authz)",
		"ttl_seconds":   300,
	}
	envBytes, _ := json.MarshalIndent(envelope, "", "  ")

	return okObj(map[string]any{
		// WIMSE outputs
		"wimseSub":       agentSub,
		"wimseTarget":    wimseTarget,
		"wimseChainHash": chainHash,
		"wimseToken":     truncate(wTok),
		"wimseProof":     truncate(wProof),
		// CB4A simulated outputs
		"cb4aEnvelope":   string(envBytes),
		"cb4aDecision":   "Tier 1 (auto-approved: scope within baseline)",
		"cb4aTokenType":  "OAuth 2.0 bearer (RFC 8693 token exchange)",
		"cb4aTokenScope": "billing:invoices:read",
		"cb4aTokenTTL":   "300s, non-renewable",
		"cb4aDPoP":       "bound to ephemeral key (RFC 9449)",
	})
}

// ── OBO delegation ────────────────────────────────────────────────────────────

// oboSimulate runs the full On-Behalf-Of flow in one call and returns a
// structured trace suitable for the demo animation.
//
// JS signature: agentFabric.oboSimulate(requestedScope) → {ok, steps:[]}
func oboSimulate(this js.Value, args []js.Value) any {
	requestedScope := "read:calendar write:booking"
	if len(args) > 0 && args[0].Type() == js.TypeString && args[0].String() != "" {
		requestedScope = args[0].String()
	}

	// ── key generation ──────────────────────────────────────────────────────
	idpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate IdP key: " + err.Error())
	}
	agentIdpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate agent IdP key: " + err.Error())
	}
	agentKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate agent key: " + err.Error())
	}
	oboKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return errObj("generate OBO AS key: " + err.Error())
	}

	const (
		idpID      = "https://idp.example.com"
		asID       = "https://as.example.com"
		agentSubj  = "spiffe://example.com/agents/booking-assistant"
		userSubj   = "user:alice@example.com"
		userEmail  = "alice@example.com"
		userScope  = "read:calendar write:booking read:contacts"
		resourceID = "https://booking-service.example.com"
	)

	steps := []any{}
	addStep := func(actor, label, detail string) {
		steps = append(steps, map[string]any{
			"actor":  actor,
			"label":  label,
			"detail": detail,
		})
	}

	// Step 1: IdP issues user token.
	userIssuer := obo.NewUserIssuer(idpID, idpKP.Private, time.Hour)
	userToken, err := userIssuer.Issue(userSubj, userEmail, userScope, asID)
	if err != nil {
		return errObj("issue user token: " + err.Error())
	}
	addStep("IdP", "Issue user token",
		"sub="+userSubj+" scope=\""+userScope+"\"  typ=user+jwt")

	// Step 2: Agent IdP issues AgentToken.
	agentIssuer := identity.NewAgentIssuer(asID, agentIdpKP.Private, time.Hour)
	agentToken, err := agentIssuer.Issue(identity.IssueOptions{
		Subject:     agentSubj,
		Role:        identity.RoleOrchestrator,
		WorkloadKey: agentKP.Public,
	})
	if err != nil {
		return errObj("issue agent token: " + err.Error())
	}
	addStep("Agent IdP", "Issue AgentToken",
		"sub="+agentSubj+"  typ=agent+jwt")

	// Step 3: Agent presents both tokens to OBO endpoint.
	addStep("Agent", "OBO request to AS",
		"grant_type=token-exchange  subject_token=user+jwt  actor_token=agent+jwt  scope=\""+requestedScope+"\"")

	agentValidator := identity.NewAgentValidator(asID, agentIdpKP.Public)
	userValidator := obo.NewUserValidator(idpID, idpKP.Public)
	oboIssuer := obo.NewOBOIssuer(asID, oboKP.Private, agentValidator, userValidator, 5*time.Minute)

	oboToken, err := oboIssuer.Issue(agentToken, userToken, resourceID, requestedScope)
	if err != nil {
		return errObj("issue OBO token: " + err.Error())
	}

	// Step 4: AS validates and issues delegated token.
	addStep("AS (OBO endpoint)", "Validate both tokens — issue delegated token",
		"✓ user token valid  ✓ agent token valid  ✓ scope \""+requestedScope+"\" ⊆ user scope  → issue obo+jwt")

	// Step 5: Agent calls resource with OBO token.
	addStep("Agent", "Call resource with OBO token",
		"Authorization: Bearer <obo+jwt>  aud="+resourceID)

	// Step 6: Resource validates and reads both identities.
	oboValidator := obo.NewOBOValidator(asID, oboKP.Public)
	result, err := oboValidator.Validate(oboToken, resourceID)
	if err != nil {
		return errObj("validate OBO token: " + err.Error())
	}
	addStep("Booking Service", "Validate OBO token — see both identities",
		"sub (user)="+result.UserID+"  act.sub (agent)="+result.AgentID+"  scope=\""+result.Scope+"\"")

	_ = userToken
	_ = agentToken
	return okObj(map[string]any{
		"steps":     steps,
		"userID":    result.UserID,
		"agentID":   result.AgentID,
		"scope":     result.Scope,
		"oboTyp":    "obo+jwt",
		"userTyp":   "user+jwt",
		"agentTyp":  "agent+jwt",
	})
}

// ── WASM registration ─────────────────────────────────────────────────────────

func main() {
	js.Global().Set("agentFabric", js.ValueOf(map[string]any{
		"setup":                      js.FuncOf(setup),
		"issueOrchestratorToken":     js.FuncOf(issueOrchestratorToken),
		"delegateToExecutor":         js.FuncOf(delegateToExecutor),
		"validateChain":              js.FuncOf(validateChain),
		"generateProof":              js.FuncOf(generateProof),
		"simulateReplayAttack":       js.FuncOf(simulateReplayAttack),
		"simulateTampering":          js.FuncOf(simulateTampering),
		// OID-FED federation (cross-org agents)
		"setupFederation":            js.FuncOf(setupFederation),
		"issueOrgBAgentToken":        js.FuncOf(issueOrgBAgentToken),
		"validateFederatedToken":     js.FuncOf(validateFederatedToken),
		// mTLS token-cert binding
		"simulateMTLSBinding":        js.FuncOf(simulateMTLSBinding),
		// CB4A static comparison (kept for backward compat)
		"simulateCredentialBroker":   js.FuncOf(simulateCredentialBroker),
		// CB4A live interactive demo
		"cb4aInit":    js.FuncOf(cb4aInit),
		"cb4aSubmit":  js.FuncOf(cb4aSubmit),
		"cb4aApprove": js.FuncOf(cb4aApprove),
		"cb4aDeny":    js.FuncOf(cb4aDeny),
		"cb4aMint":    js.FuncOf(cb4aMint),
		"cb4aAPICall": js.FuncOf(cb4aAPICall),
		"cb4aAudit":   js.FuncOf(cb4aAudit),
		// OBO delegation flow
		"oboSimulate": js.FuncOf(oboSimulate),
		// x402 payment flow
		"x402Init":            js.FuncOf(x402Init),
		"x402HitAPI":          js.FuncOf(x402HitAPI),
		"x402RequestSpending": js.FuncOf(x402RequestSpending),
		"x402Approve":         js.FuncOf(x402Approve),
		"x402MintCred":        js.FuncOf(x402MintCred),
		"x402Pay":             js.FuncOf(x402Pay),
		"x402GetAudit":        js.FuncOf(x402GetAudit),
	}))
	<-make(chan struct{}) // block forever
}

// ── helpers ───────────────────────────────────────────────────────────────────

func okObj(data map[string]any) map[string]any {
	data["ok"] = true
	return data
}

func errObj(msg string) map[string]any {
	return map[string]any{"ok": false, "error": msg}
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:40] + "…" + s[len(s)-20:]
	}
	return s
}

func splitJWT(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

var _ = fmt.Sprintf // ensure fmt is used
