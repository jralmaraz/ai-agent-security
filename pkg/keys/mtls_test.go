package keys_test

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

func TestGenerateCA(t *testing.T) {
	ca, err := keys.GenerateCA("agents.example")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if ca.Cert == nil || ca.Key == nil || len(ca.CertPEM) == 0 {
		t.Fatal("incomplete CABundle")
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert IsCA must be true")
	}
	want := "WIMSE CA \u2013 agents.example"
	if ca.Cert.Subject.CommonName != want {
		t.Errorf("CN: want %q got %q", want, ca.Cert.Subject.CommonName)
	}
}

func TestIssueAgentCert_SPIFFE(t *testing.T) {
	ca, _ := keys.GenerateCA("agents.example")
	kp, _ := keys.GenerateECKeyPair()
	const uri = "spiffe://agents.example/agent/orchestrator"

	wc, err := ca.IssueAgentCert(uri, kp.Public, nil)
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}
	if len(wc.Cert.URIs) == 0 || wc.Cert.URIs[0].String() != uri {
		t.Errorf("URI SAN: want %q got %v", uri, wc.Cert.URIs)
	}
	// Cert must be verifiable against the issuing CA.
	pool := ca.CertPool()
	if _, err := wc.Cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("cert chain verify: %v", err)
	}
}

func TestIssueAgentCert_WIMSE(t *testing.T) {
	ca, _ := keys.GenerateCA("agents.example")
	kp, _ := keys.GenerateECKeyPair()
	const uri = "wimse://agents.example/agent/tool-caller"

	wc, err := ca.IssueAgentCert(uri, kp.Public, nil)
	if err != nil {
		t.Fatalf("IssueAgentCert: %v", err)
	}
	if len(wc.Cert.URIs) == 0 || wc.Cert.URIs[0].String() != uri {
		t.Errorf("URI SAN: want %q got %v", uri, wc.Cert.URIs)
	}
}

func TestIssueAgentCert_InvalidURI(t *testing.T) {
	ca, _ := keys.GenerateCA("agents.example")
	kp, _ := keys.GenerateECKeyPair()
	_, err := ca.IssueAgentCert("not-absolute", kp.Public, nil)
	if err == nil {
		t.Error("expected error for relative URI")
	}
}

// TestMTLS_Handshake verifies a full mutual TLS handshake between a gateway
// server and an agent client, both using certs issued by the same CA.
func TestMTLS_Handshake(t *testing.T) {
	ca, _ := keys.GenerateCA("agents.example")

	// Gateway server cert — needs IP SAN for 127.0.0.1 so the client can verify hostname.
	gwKP, _ := keys.GenerateECKeyPair()
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

	// Agent client cert.
	agKP, _ := keys.GenerateECKeyPair()
	agCert, err := ca.IssueAgentCert("spiffe://agents.example/agent/test", agKP.Public, nil)
	if err != nil {
		t.Fatalf("IssueAgentCert (agent): %v", err)
	}
	clientTLS, err := keys.NewClientTLSConfig(ca.CertPool(), agCert, agKP.Private)
	if err != nil {
		t.Fatalf("NewClientTLSConfig: %v", err)
	}

	// Start TLS server.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	// mTLS client request.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 got %d", resp.StatusCode)
	}
}

// TestMTLS_WrongCA_Rejected verifies that an agent cert issued by an untrusted CA
// is rejected at the TLS handshake layer (before any HTTP processing).
func TestMTLS_WrongCA_Rejected(t *testing.T) {
	caA, _ := keys.GenerateCA("trust-a.example")
	caB, _ := keys.GenerateCA("trust-b.example")

	// Gateway trusts only CA-A.
	gwKP, _ := keys.GenerateECKeyPair()
	gwCert, _ := caA.IssueAgentCert("spiffe://trust-a.example/gateway", gwKP.Public, &keys.CertOptions{
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	})
	serverTLS, _ := keys.NewServerTLSConfig(caA.CertPool(), gwCert, gwKP.Private)

	// Agent cert issued by CA-B (not trusted by gateway).
	agKP, _ := keys.GenerateECKeyPair()
	agCert, _ := caB.IssueAgentCert("spiffe://trust-b.example/agent/test", agKP.Public, nil)
	// Client trusts the server (CA-A), but presents a cert from CA-B.
	clientTLS, _ := keys.NewClientTLSConfig(caA.CertPool(), agCert, agKP.Private)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = serverTLS
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Error("expected TLS rejection for agent cert from untrusted CA")
	}
}
