// Package identitychaining implements cross-trust-domain identity propagation
// for AI agent workloads following draft-ietf-oauth-identity-chaining-17.
//
// An agent holding an AgentToken (agent+jwt) from domain A can present it to
// domain A's token endpoint to receive a JWT Authorization Grant
// (typ: jwt-authz-grant) that is accepted by domain B's token endpoint.
//
// This enables cross-domain agent calls without pre-shared secrets between
// the domains — domain B only needs domain A's public key.
//
// Grant issuance flow:
//  1. Agent presents its AgentToken to domain A's GrantIssuer
//  2. GrantIssuer validates the AgentToken and issues a JWT Authorization Grant
//     addressed to domain B's token endpoint (in aud)
//  3. Agent presents the grant to domain B's GrantValidator
//  4. Domain B extracts the agent's SPIFFE ID from the grant's sub claim
package identitychaining

import "github.com/golang-jwt/jwt/v5"

// GrantTokenType is the JWT typ header value for JWT Authorization Grants
// per draft-ietf-oauth-identity-chaining-17 §5.
const GrantTokenType = "jwt-authz-grant"

// ActorClaims represents an RFC 8693 §4.1 actor claim embedded in the grant.
//
// In a delegation scenario, sub carries the original agent's SPIFFE ID while
// act.sub identifies the agent actually making the cross-domain call. In
// single-agent flows these may be the same. Nested act chains represent prior
// actors — the current actor is always the outermost act.
type ActorClaims struct {
	// Sub is the SPIFFE URI or other identity of the acting party.
	Sub string `json:"sub"`
	// Act optionally chains to a prior actor (nested delegation).
	Act *ActorClaims `json:"act,omitempty"`
}

// GrantClaims is the JWT payload for a JWT Authorization Grant.
type GrantClaims struct {
	jwt.RegisteredClaims
	// Act identifies the agent making the cross-domain call on behalf of the subject
	// (RFC 8693 §4.1). Optional — nil when the subject and actor are the same party.
	Act *ActorClaims `json:"act,omitempty"`
}
