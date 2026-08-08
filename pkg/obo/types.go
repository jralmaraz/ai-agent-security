// Package obo implements the OAuth 2.0 On-Behalf-Of (OBO) delegation flow.
//
// OBO lets an agent act on behalf of a user: the agent presents its own identity
// token plus the user's token to an Authorization Server; the AS issues a delegated
// token where sub=user.sub (the human) and act.sub=agent.sub (the agent acting).
// The receiving service can see both identities in one token — no invisible chain.
//
// Standards basis:
//   - RFC 8693 §4.1 (actor claim / act)
//   - OAuth 2.0 Token Exchange grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//   - Microsoft OBO ("on_behalf_of") — widely deployed pattern this formalises
package obo

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// OBOTokenType is the typ header value for delegated OBO tokens.
	OBOTokenType = "obo+jwt"

	// UserTokenType is the typ header value for user identity tokens issued by
	// the simulated IdP (UserIssuer). Production IdPs use "at+jwt" or similar.
	UserTokenType = "user+jwt"

	defaultOBOTTL  = 5 * time.Minute
	defaultUserTTL = 60 * time.Minute
)

// ActorClaims is the RFC 8693 §4.1 actor claim embedded in an OBO token.
// act.sub identifies the agent that is acting on behalf of the token's sub (user).
type ActorClaims struct {
	Subject string `json:"sub"`
}

// OBOClaims are the JWT payload claims of a delegated OBO token.
//
//   - sub  = user's identity (the human on whose behalf the agent acts)
//   - act  = agent's identity (who is actually making the call)
//   - scope = granted scopes (intersection of user consent and agent request)
type OBOClaims struct {
	jwt.RegisteredClaims
	// Act identifies the agent acting on behalf of sub (RFC 8693 §4.1).
	Act *ActorClaims `json:"act,omitempty"`
	// Scope lists the granted OAuth scopes, space-separated.
	Scope string `json:"scope,omitempty"`
}

// UserClaims are the JWT payload claims of a user identity token.
// In production these come from an IdP (Entra ID, Auth0, Okta, etc.).
type UserClaims struct {
	jwt.RegisteredClaims
	// Scope lists the OAuth scopes the user has consented to, space-separated.
	Scope string `json:"scope,omitempty"`
	// Email is the user's email address.
	Email string `json:"email,omitempty"`
}
