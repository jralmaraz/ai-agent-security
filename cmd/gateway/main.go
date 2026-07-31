// Command gateway is the WIMSE Agent Fabric gateway — an MCP-compatible HTTP
// proxy that validates agent identity chains (AgentToken + AgentProofToken)
// and enforces fine-grained authorization before forwarding to tool servers.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/internal/authz"
	"github.com/jralmaraz/wimse-agent-fabric/internal/gateway"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
)

func main() {
	port := flag.String("port", "8080", "listen port")
	issuerID := flag.String("issuer", "https://idp.example", "trusted IdP issuer ID")
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

	srv := gateway.New(gateway.Config{
		Validators:     map[string]*identity.AgentValidator{*issuerID: validator},
		ProofValidator: identity.NewProofValidator(),
		Authz:          a,
		Routes: map[string]string{
			"tool:echo": "http://localhost:9090",
		},
	})

	httpSrv := &http.Server{
		Addr:         ":" + *port,
		Handler:      srv,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("agent gateway listening", "port", *port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen", "err", err)
			os.Exit(1)
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
