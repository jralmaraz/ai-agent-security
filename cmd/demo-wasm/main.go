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

	anchorJWK, _ := keys.PublicKeyToJWK(fedAnchorPub, "anchor-key")
	orgBJWK, _ := keys.PublicKeyToJWK(fedOrgBPub, "orgb-key")

	ec, _ := federation.ParseEntityConfiguration(fedOrgBEC)
	ss, _ := federation.ParseSubordinateStatement(fedOrgBSS)

	return okObj(map[string]any{
		"anchorID":      fedAnchorID,
		"orgBID":        fedOrgBID,
		"anchorJWK":     anchorJWK,
		"orgBJWK":       orgBJWK,
		"ecIss":         ec.Issuer,
		"ecHints":       ec.AuthorityHints,
		"ssIss":         ss.Issuer,
		"ssSub":         ss.Subject,
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

	return okObj(map[string]any{
		"subject":          va.Claims.Subject,
		"issuer":           va.Claims.Issuer,
		"resolvedViaChain": true,
		"trustAnchor":      fedAnchorID,
		"resolvedKey":      orgBJWK,
	})
}

// ── WASM registration ─────────────────────────────────────────────────────────

func main() {
	js.Global().Set("agentFabric", js.ValueOf(map[string]any{
		"setup":                  js.FuncOf(setup),
		"issueOrchestratorToken": js.FuncOf(issueOrchestratorToken),
		"delegateToExecutor":     js.FuncOf(delegateToExecutor),
		"validateChain":          js.FuncOf(validateChain),
		"generateProof":          js.FuncOf(generateProof),
		"simulateReplayAttack":   js.FuncOf(simulateReplayAttack),
		"simulateTampering":      js.FuncOf(simulateTampering),
		// OID-FED federation (cross-org agents)
		"setupFederation":        js.FuncOf(setupFederation),
		"issueOrgBAgentToken":    js.FuncOf(issueOrgBAgentToken),
		"validateFederatedToken": js.FuncOf(validateFederatedToken),
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
