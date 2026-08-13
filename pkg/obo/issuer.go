package obo

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jralmaraz/ai-agent-security/pkg/identity"
	"github.com/golang-jwt/jwt/v5"
)

// OBOIssuer is the Authorization Server's On-Behalf-Of endpoint.
//
// It validates an agent's AgentToken and a user's identity token, then issues
// a delegated OBO token where:
//
//   - sub  = user.sub  (the human user — who authorised the action)
//   - act  = agent.sub (the SPIFFE ID of the acting agent)
//   - scope = requestedScope ∩ user.scope
//
// This makes delegation chains visible: any downstream service can read both
// the human user's identity AND the agent's identity from a single token.
//
// If an SDUserValidator is configured (via WithSDUserValidator), Issue also
// accepts SD-JWT user tokens (wire format: <JWT>~<disc1>~). In that case the
// AS validates only the disclosures the agent chose to reveal; any email
// disclosure is forwarded into the OBO token's email claim.
type OBOIssuer struct {
	issuerID        string
	key             *ecdsa.PrivateKey
	agentValidator  *identity.AgentValidator
	userValidator   *UserValidator
	sdUserValidator *SDUserValidator // optional; enables SD-JWT user token path
	ttl             time.Duration
}

// NewOBOIssuer creates an OBOIssuer.
//
//   - issuerID: this AS's identifier (becomes iss in the OBO token)
//   - key: this AS's signing key
//   - agentValidator: validates the incoming AgentToken
//   - userValidator: validates the incoming user identity token
//   - ttl: OBO token lifetime; zero uses 5 minutes
func NewOBOIssuer(
	issuerID string,
	key *ecdsa.PrivateKey,
	agentValidator *identity.AgentValidator,
	userValidator *UserValidator,
	ttl time.Duration,
) *OBOIssuer {
	if ttl == 0 {
		ttl = defaultOBOTTL
	}
	return &OBOIssuer{
		issuerID:       issuerID,
		key:            key,
		agentValidator: agentValidator,
		userValidator:  userValidator,
		ttl:            ttl,
	}
}

// WithSDUserValidator attaches an SDUserValidator so that the OBOIssuer can
// accept SD-JWT user tokens in addition to plain JWTs.
// Call this after NewOBOIssuer to opt in to the SD-JWT path.
func (o *OBOIssuer) WithSDUserValidator(v *SDUserValidator) *OBOIssuer {
	o.sdUserValidator = v
	return o
}

// Issue validates the agentToken and userToken, then issues an OBO token.
//
//   - agentToken: the agent's AgentToken (proves agent identity)
//   - userToken: the user's identity token from the IdP (proves user delegated to agent)
//   - targetAudience: the resource/service the OBO token is issued for
//   - requestedScope: space-separated scopes; must be a subset of the user token's scope.
//     Pass "" to inherit all scopes from the user token.
func (o *OBOIssuer) Issue(agentToken, userToken, targetAudience, requestedScope string) (string, error) {
	if agentToken == "" {
		return "", errors.New("agent token is required")
	}
	if userToken == "" {
		return "", errors.New("user token is required")
	}
	if targetAudience == "" {
		return "", errors.New("target audience is required")
	}

	// Validate agent identity.
	agentResult, err := o.agentValidator.Validate(agentToken)
	if err != nil {
		return "", fmt.Errorf("validate agent token: %w", err)
	}

	// Validate user identity.
	// SD-JWT user tokens contain a ~ separator; route them through SDUserValidator.
	var userSubject, userScope, userEmail string
	if strings.Contains(userToken, "~") {
		if o.sdUserValidator == nil {
			return "", errors.New("SD-JWT user token presented but no SDUserValidator configured")
		}
		sdResult, sdErr := o.sdUserValidator.Validate(userToken, o.issuerID)
		if sdErr != nil {
			return "", fmt.Errorf("validate SD-JWT user token: %w", sdErr)
		}
		userSubject = sdResult.Subject
		userScope = sdResult.Scope
		userEmail = sdResult.RevealedClaims["email"] // empty if not revealed
	} else {
		userClaims, plainErr := o.userValidator.Validate(userToken, o.issuerID)
		if plainErr != nil {
			return "", fmt.Errorf("validate user token: %w", plainErr)
		}
		userSubject = userClaims.Subject
		userScope = userClaims.Scope
	}

	// Resolve granted scope (intersection of user grant and request).
	grantedScope, err := resolveScope(userScope, requestedScope)
	if err != nil {
		return "", err
	}

	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := OBOClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    o.issuerID,
			Subject:   userSubject, // sub = the human user
			Audience:  jwt.ClaimStrings{targetAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(o.ttl)),
			ID:        base64.RawURLEncoding.EncodeToString(jtiRaw),
		},
		Act:   &ActorClaims{Subject: agentResult.Claims.Subject}, // act.sub = the agent
		Scope: grantedScope,
		Email: userEmail, // non-empty only when agent revealed the email SD disclosure
	}

	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["typ"] = OBOTokenType
	return t.SignedString(o.key)
}

// resolveScope returns the intersection of granted (from user token) and requested scopes.
// If requested is empty, all granted scopes are returned unchanged.
// Returns an error if any requested scope is not in the granted set.
func resolveScope(granted, requested string) (string, error) {
	if requested == "" {
		return granted, nil
	}
	grantedSet := scopeSet(granted)
	requestedList := strings.Fields(requested)
	for _, s := range requestedList {
		if !grantedSet[s] {
			return "", fmt.Errorf("requested scope %q not in user's granted scopes", s)
		}
	}
	return strings.Join(requestedList, " "), nil
}

func scopeSet(scope string) map[string]bool {
	m := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		m[s] = true
	}
	return m
}
