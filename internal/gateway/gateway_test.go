package gateway_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/ai-agent-security/internal/authz"
	"github.com/jralmaraz/ai-agent-security/internal/gateway"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/jralmaraz/ai-agent-security/pkg/ssfreceiver"
)

// ── test fixtures ─────────────────────────────────────────────────────────────

const (
	issuerID = "https://idp.example"
	toolName = "tool:echo"
	agentSub = "spiffe://cloud-a.example/agent/orchestrator"
)

func mustKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, &priv.PublicKey
}

type fixture struct {
	issuer    *identity.AgentIssuer
	validator *identity.AgentValidator
	idpPriv   *ecdsa.PrivateKey
	wlPriv    *ecdsa.PrivateKey
	wlPub     *ecdsa.PublicKey
	gw        http.Handler
	gwServer  *httptest.Server // real server for proxy tests (avoids CloseNotify panic)
	upstream  *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	idpPriv, idpPub := mustKey(t)
	wlPriv, wlPub := mustKey(t)

	issuer := identity.NewAgentIssuer(issuerID, idpPriv, time.Hour)
	validator := identity.NewAgentValidator(issuerID, idpPub)

	// Upstream echo server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"echo": "ok"})
	}))
	t.Cleanup(upstream.Close)

	a := authz.NewInMemoryAuthorizer()
	a.Allow(agentSub, toolName, authz.ActionCall)

	gw := gateway.New(gateway.Config{
		Validators:     map[string]*identity.AgentValidator{issuerID: validator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes:         map[string]string{toolName: upstream.URL},
	})

	gwServer := httptest.NewServer(gw)
	t.Cleanup(gwServer.Close)

	return &fixture{
		issuer:    issuer,
		validator: validator,
		idpPriv:   idpPriv,
		wlPriv:    wlPriv,
		wlPub:     wlPub,
		gw:        gw,
		gwServer:  gwServer,
		upstream:  upstream,
	}
}

func (f *fixture) issueToken(t *testing.T) string {
	t.Helper()
	tok, err := f.issuer.Issue(identity.IssueOptions{
		Subject:     agentSub,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: f.wlPub,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// buildRequest creates a real HTTP request to the gateway test server.
// target is the full URL (e.g. "http://127.0.0.1:PORT/tools/echo/hello").
func (f *fixture) buildRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	leafTok := f.issueToken(t)
	chain := identity.AgentChain{leafTok}

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   target,
		Chain:       chain,
		WorkloadKey: f.wlPriv,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(authz.HeaderAgentIdentityToken, leafTok)
	req.Header.Set(authz.HeaderAgentChainToken, chain.String())
	req.Header.Set(authz.HeaderAgentProofToken, proof)
	return req
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestGateway_Health(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	f.gw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("health: want 200 got %d", w.Code)
	}
}

func TestGateway_HappyPath(t *testing.T) {
	f := newFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"
	req := f.buildRequest(t, http.MethodGet, target)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 got %d", resp.StatusCode)
	}
}

func TestGateway_MissingIdentityToken(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/tools/echo/hello", nil)
	w := httptest.NewRecorder()
	f.gw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", w.Code)
	}
}

func TestGateway_MissingChainToken(t *testing.T) {
	f := newFixture(t)
	leafTok := f.issueToken(t)
	req := httptest.NewRequest(http.MethodGet, "/tools/echo/hello", nil)
	req.Header.Set(authz.HeaderAgentIdentityToken, leafTok)
	w := httptest.NewRecorder()
	f.gw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", w.Code)
	}
}

func TestGateway_MissingProofToken(t *testing.T) {
	f := newFixture(t)
	leafTok := f.issueToken(t)
	chain := identity.AgentChain{leafTok}
	req := httptest.NewRequest(http.MethodGet, "/tools/echo/hello", nil)
	req.Header.Set(authz.HeaderAgentIdentityToken, leafTok)
	req.Header.Set(authz.HeaderAgentChainToken, chain.String())
	w := httptest.NewRecorder()
	f.gw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", w.Code)
	}
}

func TestGateway_TamperedIdentityToken(t *testing.T) {
	f := newFixture(t)
	target := "https://gateway.example/tools/echo/hello"
	req := f.buildRequest(t, http.MethodGet, target)
	// Replace the identity token with a tampered one (zeroed last part).
	req.Header.Set(authz.HeaderAgentIdentityToken, "aaa.bbb.ccc")
	w := httptest.NewRecorder()
	f.gw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 got %d", w.Code)
	}
}

func TestGateway_Unauthorized_Subject(t *testing.T) {
	f := newFixture(t)
	idpPriv, idpPub := mustKey(t)
	wlPriv, wlPub := mustKey(t)

	// Issuer for a different, unknown agent.
	unknownIssuer := identity.NewAgentIssuer(issuerID, idpPriv, time.Hour)
	unknownValidator := identity.NewAgentValidator(issuerID, idpPub)

	tok, _ := unknownIssuer.Issue(identity.IssueOptions{
		Subject:     "spiffe://evil.example/agent/bad-actor",
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: wlPub,
	})
	chain := identity.AgentChain{tok}
	// Use path-only so httptest defaults host "example.com" and middleware builds
	// "https://example.com/tools/echo/hello" — must match the proof aud exactly.
	const reqTarget = "https://gateway.example/tools/echo/hello"
	proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   reqTarget,
		Chain:       chain,
		WorkloadKey: wlPriv,
	})

	// Register the unknown validator so tokens validate structurally but are not authorized.
	a := authz.NewInMemoryAuthorizer()
	a.Allow(agentSub, toolName, authz.ActionCall) // only agentSub allowed, not bad-actor

	gw := gateway.New(gateway.Config{
		Validators:     map[string]*identity.AgentValidator{issuerID: unknownValidator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes:         map[string]string{toolName: f.upstream.URL},
	})

	req := httptest.NewRequest(http.MethodGet, reqTarget, nil)
	req.Header.Set(authz.HeaderAgentIdentityToken, tok)
	req.Header.Set(authz.HeaderAgentChainToken, chain.String())
	req.Header.Set(authz.HeaderAgentProofToken, proof)
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403 got %d: %s", w.Code, w.Body.String())
	}
}

func TestGateway_ReplayAttack(t *testing.T) {
	f := newFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"
	req := f.buildRequest(t, http.MethodGet, target)

	resp1, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: want 200 got %d", resp1.StatusCode)
	}

	// Replay the exact same request (same proof token jti).
	// Re-create the request with the same headers (http.Request cannot be reused).
	req2, _ := http.NewRequest(http.MethodGet, target, nil)
	req2.Header = req.Header.Clone()
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("replay Do: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay: want 401 got %d", resp2.StatusCode)
	}
}

func TestGateway_RevokedAgent(t *testing.T) {
	idpPriv, idpPub := mustKey(t)
	wlPriv, wlPub := mustKey(t)

	issuer := identity.NewAgentIssuer(issuerID, idpPriv, time.Hour)
	validator := identity.NewAgentValidator(issuerID, idpPub)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	a := authz.NewInMemoryAuthorizer()
	a.Allow(agentSub, toolName, authz.ActionCall)

	recv := ssfreceiver.NewReceiver()
	rem := ssfreceiver.NewAgentRemediation(recv)

	gw := gateway.New(gateway.Config{
		Validators:     map[string]*identity.AgentValidator{issuerID: validator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes:         map[string]string{toolName: upstream.URL},
		Remediation:    rem,
	})

	gwServer := httptest.NewServer(gw)
	t.Cleanup(gwServer.Close)

	buildReq := func(targetURL string) *http.Request {
		tok, _ := issuer.Issue(identity.IssueOptions{
			Subject:     agentSub,
			Role:        identity.RoleOrchestrator,
			ChainDepth:  0,
			WorkloadKey: wlPub,
		})
		chain := identity.AgentChain{tok}
		proof, _ := identity.GenerateProof(identity.ProofGenerateOptions{
			TargetURI:   targetURL,
			Chain:       chain,
			WorkloadKey: wlPriv,
		})
		req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
		req.Header.Set(authz.HeaderAgentIdentityToken, tok)
		req.Header.Set(authz.HeaderAgentChainToken, chain.String())
		req.Header.Set(authz.HeaderAgentProofToken, proof)
		return req
	}

	// Before revocation: request should succeed.
	resp1, err := http.DefaultClient.Do(buildReq(gwServer.URL + "/tools/echo/check1"))
	if err != nil {
		t.Fatalf("before revocation Do: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("before revocation: want 200 got %d", resp1.StatusCode)
	}

	// Push a session-revoked SET for agentSub via the gateway's /ssf/events endpoint.
	type setClaims struct {
		jwt.RegisteredClaims
		Events map[string]json.RawMessage `json:"events"`
	}
	evPayload, _ := json.Marshal(map[string]any{
		"subject": map[string]any{"format": "spiffe", "sub": agentSub},
	})
	sc := setClaims{
		RegisteredClaims: jwt.RegisteredClaims{ID: "revoke-jti-gw-test", Issuer: "https://idp.example"},
		Events: map[string]json.RawMessage{
			ssfreceiver.EventTypeSessionRevoked: json.RawMessage(evPayload),
		},
	}
	setTok, _ := jwt.NewWithClaims(jwt.SigningMethodNone, sc).SignedString(jwt.UnsafeAllowNoneSignatureType)

	ssfReq, _ := http.NewRequest(http.MethodPost, gwServer.URL+"/ssf/events", strings.NewReader(setTok))
	ssfReq.Header.Set("Content-Type", "application/secevent+jwt")
	ssfResp, err := http.DefaultClient.Do(ssfReq)
	if err != nil {
		t.Fatalf("SSF push: %v", err)
	}
	ssfResp.Body.Close()
	if ssfResp.StatusCode != http.StatusAccepted {
		t.Fatalf("SSF push: want 202 got %d", ssfResp.StatusCode)
	}

	// After revocation: same agent should be rejected.
	resp2, err := http.DefaultClient.Do(buildReq(gwServer.URL + "/tools/echo/check2"))
	if err != nil {
		t.Fatalf("after revocation Do: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("after revocation: want 401 got %d", resp2.StatusCode)
	}
	if www := resp2.Header.Get("WWW-Authenticate"); !strings.Contains(www, "agent revoked") {
		t.Errorf("expected WWW-Authenticate to mention 'agent revoked', got %q", www)
	}
}
