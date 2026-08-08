package authz

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jralmaraz/ai-agent-security/pkg/identity"
)

const (
	// ContextKeyAgent is the Gin context key for the validated agent.
	ContextKeyAgent = "wimse.agent"
	// ContextKeyChain is the Gin context key for the parsed delegation chain.
	ContextKeyChain = "wimse.chain"
)

// AgentAuthHeaders are the HTTP headers carrying identity tokens.
const (
	HeaderAgentIdentityToken = "Agent-Identity-Token"
	HeaderAgentChainToken    = "Agent-Chain-Token"
	HeaderAgentProofToken    = "Agent-Proof-Token"
)

// AgentAuth returns a Gin middleware that validates WIMSE agent identity.
//
// On each request it:
//  1. Reads Agent-Identity-Token (the leaf AgentToken for this hop)
//  2. Validates it with the provided AgentValidator
//  3. Reads Agent-Chain-Token (the full delegation chain wire string)
//  4. Parses and validates the chain using the provided validators map
//  5. Reads Agent-Proof-Token and validates it (sig, aud, chain_hash, replay)
//  6. Runs an authorization check via the provided Authorizer
//  7. On success, injects ValidatedAgent and AgentChain into the Gin context
//
// object is the resource name for the authorization check (e.g. "tool:echo").
// action is the required permission.
func AgentAuth(
	leafValidator *identity.AgentValidator,
	chainValidators map[string]*identity.AgentValidator,
	proofValidator *identity.ProofValidator,
	authz Authorizer,
	object string,
	action Action,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Leaf token.
		leafTok := c.GetHeader(HeaderAgentIdentityToken)
		if leafTok == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + HeaderAgentIdentityToken})
			return
		}
		va, err := leafValidator.Validate(leafTok)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent identity token: " + err.Error()})
			return
		}

		// 2. Delegation chain.
		chainStr := c.GetHeader(HeaderAgentChainToken)
		if chainStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + HeaderAgentChainToken})
			return
		}
		chain, err := identity.ParseChain(chainStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent chain: " + err.Error()})
			return
		}
		if _, err := chain.Validate(chainValidators); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "chain validation failed: " + err.Error()})
			return
		}

		// 3. Proof token.
		proofTok := c.GetHeader(HeaderAgentProofToken)
		if proofTok == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing " + HeaderAgentProofToken})
			return
		}
		requestURI := "https://" + c.Request.Host + c.Request.RequestURI
		_, err = proofValidator.Validate(identity.ProofValidateOptions{
			ProofToken:  proofTok,
			Chain:       chain,
			RequestURI:  requestURI,
			WorkloadKey: va.WorkloadKey,
			CheckReplay: true,
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid agent proof token: " + err.Error()})
			return
		}

		// 4. Authorization check.
		decision, err := authz.Authorize(c.Request.Context(), Request{
			Subject: va.Claims.Subject,
			Object:  object,
			Action:  action,
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authz error: " + err.Error()})
			return
		}
		if !decision.Allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied", "reason": decision.Reason})
			return
		}

		// 5. Inject context.
		c.Set(ContextKeyAgent, va)
		c.Set(ContextKeyChain, chain)
		c.Next()
	}
}
