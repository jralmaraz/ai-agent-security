package txntoken

import "github.com/golang-jwt/jwt/v5"

// TokenType is the JWT typ header value for Transaction Tokens.
// Reference: draft-ietf-oauth-transaction-tokens-11 §5
const TokenType = "txntoken+jwt"

// ActorClaims represents an RFC 8693 §4.1 actor claim.
//
// It identifies the party acting on behalf of the token subject (typically a
// SPIFFE ID for an agent workload). For multi-hop delegation chains, ActorClaims
// may be nested — the outermost Act is the current actor; nested Acts are prior
// actors in chronological order, with the least-recent actor most deeply nested.
//
// Per RFC 8693 §4.1, consumers MUST apply access control policy based only on
// the current actor (outermost Act). Prior actors are informational only.
//
// Example — orchestrator acting on behalf of a user, itself delegated by a gateway:
//
//	act.sub  = "spiffe://mesh.example/agents/orchestrator"  // current actor
//	act.act.sub = "spiffe://mesh.example/gateway"           // prior actor (informational)
type ActorClaims struct {
	// Sub is the SPIFFE URI or other identity of the acting party (RFC 8693 §4.1).
	Sub string `json:"sub"`
	// Act optionally chains to a prior actor (nested delegation, RFC 8693 §4.1).
	Act *ActorClaims `json:"act,omitempty"`
}

// Claims represents the payload of an OAuth 2.0 Transaction Token (Txn-Token).
//
// Txn-Tokens propagate a user's identity and the authorization context
// granted at the entry point through an entire AI agent call chain.
// Intermediate agents do not need to re-authenticate the user; they verify
// the Txn-Token issued by the Transaction Token Service (TTS).
//
// An AgentProofToken may bind to the Txn-Token via the tth claim:
//
//	tth = base64url(SHA-256(txntoken_compact_serialization))
//
// Reference: draft-ietf-oauth-transaction-tokens-11
type Claims struct {
	jwt.RegisteredClaims
	// Txn uniquely identifies the business transaction across its entire call chain.
	Txn string `json:"txn"`
	// Act identifies the entry-point agent acting on behalf of the subject (RFC 8693 §4.1).
	// sub carries the user identity; act.sub carries the agent's SPIFFE ID.
	Act *ActorClaims `json:"act,omitempty"`
	// ReqCtx carries the request context recorded at the entry-point agent.
	ReqCtx *RequestContext `json:"rctx,omitempty"`
	// AzDetails carries authorization details granted by the Authorization Server.
	AzDetails []AuthorizationDetail `json:"azd,omitempty"`
}

// RequestContext identifies the origin of the request that initiated the transaction.
type RequestContext struct {
	// ReqIP is the IP address of the end-user client or external caller.
	ReqIP string `json:"req_ip,omitempty"`
	// ReqWL is the SPIFFE URI of the agent that acquired the Txn-Token
	// at the trust domain entry point.
	ReqWL string `json:"req_wl,omitempty"`
}

// AuthorizationDetail is a single authorization detail from the Authorization Server,
// following the Rich Authorization Requests format (RFC 9396).
type AuthorizationDetail struct {
	Type   string            `json:"type"`
	Claims map[string]string `json:"claims,omitempty"`
}
