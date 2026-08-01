package txntoken

import "github.com/golang-jwt/jwt/v5"

// TokenType is the JWT typ header value for Transaction Tokens.
// Reference: draft-ietf-oauth-transaction-tokens-11 §5
const TokenType = "txntoken+jwt"

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
