// Package gateway implements an MCP-compatible HTTP proxy that validates
// WIMSE agent identity chains before forwarding requests to tool servers.
package gateway

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/jralmaraz/ai-agent-security/internal/authz"
	"github.com/jralmaraz/ai-agent-security/pkg/federation"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
)

// Config holds gateway configuration.
type Config struct {
	// Validators maps issuer IDs to their AgentValidators (static, Phase 3).
	Validators map[string]*identity.AgentValidator

	// FederationResolver resolves unknown issuers via OID-FED trust chains (Phase 6).
	// If nil, only Validators is consulted.
	FederationResolver federation.Resolver

	// ProofValidator is the shared per-gateway replay store.
	ProofValidator *identity.ProofValidator

	// Authz is the authorization back-end.
	Authz authz.Authorizer

	// Routes maps tool names (e.g. "tool:weather-api") to their upstream base URLs.
	Routes map[string]string

	// MTLSClientCA, when non-nil, enables token-cert binding. The middleware
	// verifies that the connecting agent's TLS client certificate URI SAN
	// matches the sub claim of the Agent-Identity-Token, binding transport
	// identity to application identity. The listener must be separately
	// configured with RequireAndVerifyClientCert and this same CA pool.
	MTLSClientCA *x509.CertPool
}

// Server is the agent gateway HTTP server.
type Server struct {
	cfg    Config
	router *gin.Engine
}

// New creates a gateway Server and registers all routes.
func New(cfg Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	s := &Server{cfg: cfg, router: r}
	r.GET("/health", s.healthHandler)

	// Each configured route gets its own protected sub-path.
	for toolName, upstream := range cfg.Routes {
		toolName := toolName // capture for closure
		upstream := upstream
		upstreamURL, err := url.Parse(upstream)
		if err != nil {
			panic("invalid upstream URL for " + toolName + ": " + err.Error())
		}
		proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

		group := r.Group("/tools/" + toolNameToPath(toolName))
		group.Use(s.agentAuthMiddleware(toolName))
		group.Any("/*path", func(c *gin.Context) {
			proxy.ServeHTTP(c.Writer, c.Request)
		})
	}

	return s
}

// ServeHTTP implements http.Handler so the server can be used with httptest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// agentAuthMiddleware validates agent identity, chain, proof, and authz for a tool.
func (s *Server) agentAuthMiddleware(toolName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Leaf identity token.
		leafTok := c.GetHeader(authz.HeaderAgentIdentityToken)
		if leafTok == "" {
			abort(c, http.StatusUnauthorized, "missing "+authz.HeaderAgentIdentityToken)
			return
		}
		va, err := s.resolveAndValidate(c.Request.Context(), leafTok)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid agent identity token: "+err.Error())
			return
		}

		// 2. mTLS token-cert binding: peer certificate URI SAN must equal token sub.
		if s.cfg.MTLSClientCA != nil {
			if err := verifyMTLSBinding(c.Request, va.Claims.Subject); err != nil {
				abort(c, http.StatusUnauthorized, "mTLS binding: "+err.Error())
				return
			}
		}

		// 3. Delegation chain.
		chainStr := c.GetHeader(authz.HeaderAgentChainToken)
		if chainStr == "" {
			abort(c, http.StatusUnauthorized, "missing "+authz.HeaderAgentChainToken)
			return
		}
		chain, err := identity.ParseChain(chainStr)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid agent chain: "+err.Error())
			return
		}
		if _, err := chain.Validate(s.cfg.Validators); err != nil {
			abort(c, http.StatusUnauthorized, "chain validation failed: "+err.Error())
			return
		}

		// 4. Proof token.
		proofTok := c.GetHeader(authz.HeaderAgentProofToken)
		if proofTok == "" {
			abort(c, http.StatusUnauthorized, "missing "+authz.HeaderAgentProofToken)
			return
		}
		scheme := "https"
		if c.Request.TLS == nil {
			scheme = "http"
		}
		requestURI := scheme + "://" + c.Request.Host + c.Request.URL.RequestURI()
		if _, err := s.cfg.ProofValidator.Validate(identity.ProofValidateOptions{
			ProofToken:  proofTok,
			Chain:       chain,
			RequestURI:  requestURI,
			WorkloadKey: va.WorkloadKey,
			CheckReplay: true,
		}); err != nil {
			abort(c, http.StatusUnauthorized, "invalid agent proof token: "+err.Error())
			return
		}

		// 5. Authorization — COAZ-MCP Binding 1.0.
		// Read and restore the request body so both the authz check and the upstream
		// proxy can consume it. The tool parameters form the COAZ-MCP context element.
		toolParams := extractToolParams(c.Request)
		decision, err := s.cfg.Authz.Authorize(c.Request.Context(), authz.Request{
			Subject:    va.Claims.Subject,
			Object:     toolName,
			Action:     authz.ActionCall,
			ToolParams: toolParams, // parameter-level authorization context (COAZ-MCP §3.2)
		})
		if err != nil {
			abort(c, http.StatusInternalServerError, "authz error: "+err.Error())
			return
		}
		if decision.Pending {
			// AARP 1.0 §4 — deny but requestable: return 403 with approval endpoint.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":             "access denied — requestable",
				"pending":           true,
				"approval_endpoint": decision.ApprovalEndpoint,
				"reason":            decision.Reason,
			})
			return
		}
		if !decision.Allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied", "reason": decision.Reason})
			return
		}

		c.Set(authz.ContextKeyAgent, va)
		c.Set(authz.ContextKeyChain, chain)
		c.Next()
	}
}

// resolveAndValidate validates an agent identity token using either the static
// Validators map or the OID-FED Resolver for dynamically-discovered issuers.
func (s *Server) resolveAndValidate(ctx context.Context, tok string) (*identity.ValidatedAgent, error) {
	// Try static validators first (fast path, no network).
	va, err := validateWithAny(s.cfg.Validators, tok)
	if err == nil {
		return va, nil
	}
	// Federation fallback: peek at issuer, resolve key, build validator on the fly.
	if s.cfg.FederationResolver == nil {
		return nil, err
	}
	issuer, peekErr := peekIssuer(tok)
	if peekErr != nil {
		return nil, fmt.Errorf("peek issuer: %w", peekErr)
	}
	entity, resolveErr := s.cfg.FederationResolver.Resolve(ctx, issuer)
	if resolveErr != nil {
		return nil, fmt.Errorf("federation resolve %q: %w", issuer, resolveErr)
	}
	pub, keyErr := entity.PublicKey()
	if keyErr != nil {
		return nil, fmt.Errorf("extract key for %q: %w", issuer, keyErr)
	}
	dynValidator := identity.NewAgentValidator(issuer, pub)
	return dynValidator.Validate(tok)
}

// verifyMTLSBinding checks that the first URI SAN of the peer TLS certificate
// equals wantSub (the Agent-Identity-Token sub claim). This binds transport
// identity to application identity: a stolen token cannot be replayed without
// the matching private key.
func verifyMTLSBinding(r *http.Request, wantSub string) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate presented")
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if u.String() == wantSub {
			return nil
		}
	}
	return fmt.Errorf("cert URI SANs %v do not match token subject %q",
		r.TLS.PeerCertificates[0].URIs, wantSub)
}

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
}

// extractToolParams reads the JSON request body as MCP tool call parameters for
// COAZ-MCP Binding 1.0 §3.2 context element, then restores the body so the
// upstream proxy can also read it.
func extractToolParams(r *http.Request) map[string]any {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB cap
	if err != nil || len(body) == 0 {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body)) // restore for upstream proxy
	var params map[string]any
	if json.Unmarshal(body, &params) != nil {
		return nil // non-JSON body — tool params cannot be inspected
	}
	return params
}

// toolNameToPath converts "tool:weather-api" to "weather-api".
func toolNameToPath(name string) string {
	for i, ch := range name {
		if ch == ':' {
			return name[i+1:]
		}
	}
	return name
}
