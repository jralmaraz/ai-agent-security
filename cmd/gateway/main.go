// Command gateway is the WIMSE Agent Fabric gateway — an MCP-compatible HTTP
// proxy that validates agent identity chains (AgentToken + AgentProofToken)
// and enforces fine-grained authorization before forwarding to tool servers.
//
// Usage (plain HTTP, PoC mode):
//
//	go run ./cmd/gateway --port 8080 --issuer https://idp.example
//
// Usage (mTLS mode with auto-generated ephemeral CA):
//
//	go run ./cmd/gateway --port 8443 --mtls --trust-domain agents.example \
//	    --write-agent-creds /tmp/agent
//
// When --write-agent-creds is set, the gateway writes the following files
// so a demo agent can connect:
//
//	<prefix>-ca.pem       — CA certificate (trust anchor)
//	<prefix>-agent.pem    — agent client certificate
//	<prefix>-agent-key.pem— agent private key (mode 0600)
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"crypto/x509"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jralmaraz/ai-agent-security/internal/authz"
	"github.com/jralmaraz/ai-agent-security/internal/gateway"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/jralmaraz/ai-agent-security/pkg/keys"
)

func main() {
	port := flag.String("port", "8080", "listen port")
	issuerID := flag.String("issuer", "https://idp.example", "trusted IdP issuer ID")
	enableMTLS := flag.Bool("mtls", false, "enable mutual TLS (auto-generates ephemeral CA)")
	trustDomain := flag.String("trust-domain", "agents.example", "trust domain for auto-generated mTLS CA")
	writeAgentCreds := flag.String("write-agent-creds", "", "path prefix to write demo agent cert/key/ca files")
	flag.Parse()

	// In a real deployment the IdP public key would come from a JWKS endpoint.
	// For the PoC, generate an ephemeral key pair so the binary is self-contained.
	idpPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("generate IdP key", "err", err)
		os.Exit(1)
	}

	validator := identity.NewAgentValidator(*issuerID, &idpPriv.PublicKey)

	a := authz.NewInMemoryAuthorizer()
	// Wildcard: any validated agent may call any registered tool (PoC mode).
	a.Allow("*", "tool:echo", authz.ActionCall)

	gwCfg := gateway.Config{
		Validators:     map[string]*identity.AgentValidator{*issuerID: validator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes: map[string]string{
			"tool:echo": "http://localhost:9090",
		},
	}

	var tlsCfg *tls.Config

	if *enableMTLS {
		var ca *keys.CABundle
		var serverTLS *tls.Config
		ca, serverTLS, err = setupMTLS(*trustDomain, *writeAgentCreds)
		if err != nil {
			slog.Error("mTLS setup", "err", err)
			os.Exit(1)
		}
		gwCfg.MTLSClientCA = ca.CertPool()
		tlsCfg = serverTLS
		slog.Info("mTLS enabled", "trust_domain", *trustDomain)
	}

	srv := gateway.New(gwCfg)

	httpSrv := &http.Server{
		Addr:         ":" + *port,
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    tlsCfg,
	}

	go func() {
		if *enableMTLS {
			slog.Info("agent gateway listening (mTLS)", "port", *port)
			// TLSConfig already has Certificates set; empty strings skip file loading.
			if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("listen TLS", "err", err)
				os.Exit(1)
			}
		} else {
			slog.Info("agent gateway listening", "port", *port)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("listen", "err", err)
				os.Exit(1)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("shutdown", "err", err)
	}
	slog.Info("gateway stopped")
}

// setupMTLS generates an ephemeral CA and gateway server cert for PoC mTLS.
// If credPrefix is non-empty it also issues a demo agent cert and writes
// the CA cert, agent cert, and agent key to <credPrefix>-ca.pem etc.
func setupMTLS(trustDomain, credPrefix string) (*keys.CABundle, *tls.Config, error) {
	ca, err := keys.GenerateCA(trustDomain)
	if err != nil {
		return nil, nil, err
	}

	// Gateway server cert needs an IP SAN so agents can connect to 127.0.0.1.
	gwKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return nil, nil, err
	}
	gwCert, err := ca.IssueAgentCert(
		"spiffe://"+trustDomain+"/gateway",
		gwKP.Public,
		&keys.CertOptions{IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}},
	)
	if err != nil {
		return nil, nil, err
	}
	serverTLS, err := keys.NewServerTLSConfig(ca.CertPool(), gwCert, gwKP.Private)
	if err != nil {
		return nil, nil, err
	}

	slog.Info("ephemeral CA generated", "trust_domain", trustDomain)
	slog.Info("CA cert PEM", "pem", string(ca.CertPEM))

	if credPrefix != "" {
		if err := writeAgentCredentials(ca, trustDomain, credPrefix); err != nil {
			return nil, nil, err
		}
	}

	return ca, serverTLS, nil
}

// writeAgentCredentials issues a demo agent cert signed by ca and writes
// <prefix>-ca.pem, <prefix>-agent.pem, <prefix>-agent-key.pem.
func writeAgentCredentials(ca *keys.CABundle, trustDomain, prefix string) error {
	// Write CA cert.
	if err := os.WriteFile(prefix+"-ca.pem", ca.CertPEM, 0644); err != nil {
		return err
	}
	slog.Info("wrote CA cert", "path", prefix+"-ca.pem")

	// Issue demo agent cert (key pair used for both mTLS cert and cnf.jwk).
	agentKP, err := keys.GenerateECKeyPair()
	if err != nil {
		return err
	}
	agentSub := "spiffe://" + trustDomain + "/agent/demo"
	agentCert, err := ca.IssueAgentCert(agentSub, agentKP.Public, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+"-agent.pem", agentCert.CertPEM, 0644); err != nil {
		return err
	}
	slog.Info("wrote agent cert", "path", prefix+"-agent.pem", "sub", agentSub)

	// Write agent private key (mode 0600).
	keyDER, err := x509.MarshalECPrivateKey(agentKP.Private)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(prefix+"-agent-key.pem", keyPEM, 0600); err != nil {
		return err
	}
	slog.Info("wrote agent key", "path", prefix+"-agent-key.pem")

	return nil
}
