package gateway_test

// mTLS integration tests for the WIMSE agent gateway.
//
// These tests verify the token-cert binding property: the agent's TLS client
// certificate URI SAN must match the Agent-Identity-Token sub claim. This
// means a stolen token cannot be replayed without the private key that backs
// both the mTLS cert and the AgentToken cnf.jwk.
//
// Test matrix:
//
//	TestGateway_mTLS_HappyPath       — valid cert + matching token sub  → 200
//	TestGateway_mTLS_URISANMismatch  — valid cert but sub ≠ URI SAN     → 401
//	TestGateway_mTLS_WrongCA         — cert from untrusted CA           → TLS error
//	TestGateway_mTLS_NoClientCert    — no client cert, mTLS required    → TLS error

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/internal/authz"
	"github.com/jralmaraz/wimse-agent-fabric/internal/gateway"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

const (
	mtlsIssuerID = "https://idp.agents.example"
	mtlsToolName = "tool:echo"
	// agentSub is shared with the URI SAN in the agent certificate.
	// Using the same constant ensures the binding check passes in happy-path tests.
	mtlsAgentSub = "spiffe://agents.example/agent/orchestrator"
)

// mtlsFixture wires a full mTLS gateway stack:
//
//   - CA issues both the gateway server cert and the agent client cert
//   - Gateway Config has MTLSClientCA set → binding is enforced
//   - gwServer is a real TLS httptest.Server (not just ServeHTTP)
//   - agentClient is an http.Client presenting the agent mTLS cert
type mtlsFixture struct {
	ca         *keys.CABundle
	idpPriv    *keys.ECKeyPair
	agentKP    *keys.ECKeyPair // same key: mTLS cert + cnf.jwk + proof signing
	issuer     *identity.AgentIssuer
	validator  *identity.AgentValidator
	gwServer   *httptest.Server
	upstream   *httptest.Server
	agentClient *http.Client
}

func newMTLSFixture(t *testing.T) *mtlsFixture {
	t.Helper()

	// 1. Trust anchor CA for this trust domain.
	ca, err := keys.GenerateCA("agents.example")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// 2. Gateway server cert — IP SAN 127.0.0.1 so TLS hostname validation passes.
	gwKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("gateway key: %v", err)
	}
	gwCert, err := ca.IssueAgentCert("spiffe://agents.example/gateway", gwKP.Public, &keys.CertOptions{
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("IssueAgentCert (gateway): %v", err)
	}
	serverTLS, err := keys.NewServerTLSConfig(ca.CertPool(), gwCert, gwKP.Private)
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	// 3. Agent key pair — one key serves as:
	//    (a) the mTLS client cert key
	//    (b) the WIT cnf.jwk (IssueOptions.WorkloadKey)
	//    (c) the proof signing key (ProofGenerateOptions.WorkloadKey)
	// This shared-key design is the WIMSE identity binding property.
	agentKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	agentCert, err := ca.IssueAgentCert(mtlsAgentSub, agentKP.Public, nil)
	if err != nil {
		t.Fatalf("IssueAgentCert (agent): %v", err)
	}
	clientTLS, err := keys.NewClientTLSConfig(ca.CertPool(), agentCert, agentKP.Private)
	if err != nil {
		t.Fatalf("NewClientTLSConfig: %v", err)
	}

	// 4. IdP key pair.
	idpKP, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("idp key: %v", err)
	}
	issuer := identity.NewAgentIssuer(mtlsIssuerID, idpKP.Private, time.Hour)
	validator := identity.NewAgentValidator(mtlsIssuerID, idpKP.Public)

	// 5. Upstream echo service.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"echo": "ok"})
	}))
	t.Cleanup(upstream.Close)

	// 6. Authorization policy.
	a := authz.NewInMemoryAuthorizer()
	a.Allow(mtlsAgentSub, mtlsToolName, authz.ActionCall)

	// 7. Gateway with MTLSClientCA set (enables binding check).
	gw := gateway.New(gateway.Config{
		Validators:     map[string]*identity.AgentValidator{mtlsIssuerID: validator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes:         map[string]string{mtlsToolName: upstream.URL},
		MTLSClientCA:   ca.CertPool(),
	})

	// 8. TLS httptest server.
	gwServer := httptest.NewUnstartedServer(gw)
	gwServer.TLS = serverTLS
	gwServer.StartTLS()
	t.Cleanup(gwServer.Close)

	agentClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}

	return &mtlsFixture{
		ca:          ca,
		idpPriv:     idpKP,
		agentKP:     agentKP,
		issuer:      issuer,
		validator:   validator,
		gwServer:    gwServer,
		upstream:    upstream,
		agentClient: agentClient,
	}
}

// buildMTLSRequest creates a signed request to target with all three WIMSE
// headers and the agent's shared key (cert + proof key).
func (f *mtlsFixture) buildMTLSRequest(t *testing.T, target, sub string) *http.Request {
	t.Helper()

	leafTok, err := f.issuer.Issue(identity.IssueOptions{
		Subject:     sub,
		Role:        identity.RoleOrchestrator,
		ChainDepth:  0,
		WorkloadKey: f.agentKP.Public,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	chain := identity.AgentChain{leafTok}

	proof, err := identity.GenerateProof(identity.ProofGenerateOptions{
		TargetURI:   target,
		Chain:       chain,
		WorkloadKey: f.agentKP.Private,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(authz.HeaderAgentIdentityToken, leafTok)
	req.Header.Set(authz.HeaderAgentChainToken, chain.String())
	req.Header.Set(authz.HeaderAgentProofToken, proof)
	return req
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestGateway_mTLS_HappyPath: valid mTLS cert + matching token sub → 200.
// The agent cert URI SAN equals the AgentToken sub and the proof audience
// matches the HTTPS request URL.
func TestGateway_mTLS_HappyPath(t *testing.T) {
	f := newMTLSFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"

	req := f.buildMTLSRequest(t, target, mtlsAgentSub)
	resp, err := f.agentClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 got %d", resp.StatusCode)
	}
}

// TestGateway_mTLS_URISANMismatch: the agent presents a valid cert (trusted CA)
// but the AgentToken sub does not match the cert's URI SAN.
// The TLS handshake succeeds but the middleware rejects with 401.
func TestGateway_mTLS_URISANMismatch(t *testing.T) {
	f := newMTLSFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"

	// Token sub is a different identity than the cert URI SAN (mtlsAgentSub).
	const differentSub = "spiffe://agents.example/agent/impostor"
	req := f.buildMTLSRequest(t, target, differentSub)

	resp, err := f.agentClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401 got %d: %s", resp.StatusCode, resp.Status)
	}
}

// TestGateway_mTLS_WrongCA: agent cert is issued by a CA not trusted by the gateway.
// The TLS handshake fails before the HTTP handler is reached.
func TestGateway_mTLS_WrongCA(t *testing.T) {
	f := newMTLSFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"

	// Create a rogue agent cert from a completely different CA.
	rogueCA, err := keys.GenerateCA("rogue.example")
	if err != nil {
		t.Fatalf("GenerateCA (rogue): %v", err)
	}
	rogueKP, _ := keys.GenerateECKeyPair()
	rogueCert, _ := rogueCA.IssueAgentCert(mtlsAgentSub, rogueKP.Public, nil)
	// Client trusts the gateway's CA for server cert, but presents a rogue client cert.
	rogueTLS, _ := keys.NewClientTLSConfig(f.ca.CertPool(), rogueCert, rogueKP.Private)

	rogueClient := &http.Client{Transport: &http.Transport{TLSClientConfig: rogueTLS}}
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	_, err = rogueClient.Do(req)
	if err == nil {
		t.Error("expected TLS rejection for cert from untrusted CA")
	}
}

// TestGateway_mTLS_NoClientCert: gateway requires mTLS but client presents no cert.
// The TLS handshake fails (RequireAndVerifyClientCert).
func TestGateway_mTLS_NoClientCert(t *testing.T) {
	f := newMTLSFixture(t)
	target := f.gwServer.URL + "/tools/echo/hello"

	// Client trusts the server cert but provides no client cert.
	anonTLS := &tls.Config{RootCAs: f.ca.CertPool(), MinVersion: tls.VersionTLS13}
	anonClient := &http.Client{Transport: &http.Transport{TLSClientConfig: anonTLS}}

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	_, err := anonClient.Do(req)
	if err == nil {
		t.Error("expected TLS rejection when no client cert is presented")
	}
}
