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

	"github.com/jralmaraz/wimse-agent-fabric/pkg/cb4a"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/federation"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
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
