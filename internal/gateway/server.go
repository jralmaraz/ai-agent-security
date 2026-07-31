// Package gateway implements an MCP-compatible HTTP proxy that validates
// WIMSE agent identity chains before forwarding requests to tool servers.
package gateway

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/jralmaraz/wimse-agent-fabric/internal/authz"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
)

// Config holds gateway configuration.
type Config struct {
	// Validators maps issuer IDs to their AgentValidators (all trusted IdPs).
	Validators map[string]*identity.AgentValidator

	// ProofValidator is the shared per-gateway replay store.
	ProofValidator *identity.ProofValidator

	// Authz is the authorization back-end.
	Authz authz.Authorizer

	// Routes maps tool names (e.g. "tool:weather-api") to their upstream base URLs.
	Routes map[string]string
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
		va, err := validateWithAny(s.cfg.Validators, leafTok)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid agent identity token: "+err.Error())
			return
		}

		// 2. Delegation chain.
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

		// 3. Proof token.
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

		// 4. Authorization.
		decision, err := s.cfg.Authz.Authorize(c.Request.Context(), authz.Request{
			Subject: va.Claims.Subject,
			Object:  toolName,
			Action:  authz.ActionCall,
		})
		if err != nil {
			abort(c, http.StatusInternalServerError, "authz error: "+err.Error())
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

func abort(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
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
