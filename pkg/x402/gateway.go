package x402

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/cb4a"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
)

// PaymentGateway is the server-side component that issues x402 payment challenges
// and verifies CB4A-DPoP payment payloads.
//
// Verification steps (in order):
//
//  1. Parse CB4A access token — verify CDP signature, extract scope and AgentSVID
//  2. Confirm scope covers the required payment (asset + amount match)
//  3. Verify DPoP proof via CDP.SimulateAPICall (htm, htu, ath, exp, jti replay)
//  4. Validate WIMSE AgentToken — confirm sub matches CB4A AgentSVID
type PaymentGateway struct {
	cdp            *cb4a.CDP
	cdpPub         *ecdsa.PublicKey
	agentValidator *identity.AgentValidator
	asset          string // accepted payment asset (e.g. "AGENT_CREDIT")
	amount         string // required payment amount (e.g. "100")
}

// NewPaymentGateway creates a PaymentGateway.
//
//   - cdp: CB4A Credential Delivery Point, used for DPoP proof verification
//   - cdpPub: CDP's public signing key, used to verify CB4A access tokens
//   - agentValidator: verifies the payer's WIMSE AgentToken
//   - asset: accepted payment asset (e.g. "AGENT_CREDIT")
//   - amount: required payment amount (e.g. "100")
func NewPaymentGateway(cdp *cb4a.CDP, cdpPub *ecdsa.PublicKey, agentValidator *identity.AgentValidator, asset, amount string) *PaymentGateway {
	return &PaymentGateway{
		cdp:            cdp,
		cdpPub:         cdpPub,
		agentValidator: agentValidator,
		asset:          asset,
		amount:         amount,
	}
}

// Require returns a PaymentRequired payload for the given resource URI.
// Servers return this as JSON with HTTP status 402 Payment Required.
func (g *PaymentGateway) Require(resource string) PaymentRequired {
	return PaymentRequired{
		X402Version: X402Version,
		Accepts: []PaymentMethod{{
			Scheme:  SchemeCB4ADPOP,
			Network: NetworkWIMSE,
			Asset:   g.asset,
			Amount:  g.amount,
		}},
		Resource: resource,
		Error:    "Payment required",
	}
}

// Verify validates a payment payload and returns the authorized PaymentResult.
// Returns an error if any verification step fails.
func (g *PaymentGateway) Verify(payload PaymentPayload, method, uri string) (PaymentResult, error) {
	if payload.CB4AToken == "" {
		return PaymentResult{}, errors.New("cb4aToken is required")
	}
	if payload.DPoPProof == "" {
		return PaymentResult{}, errors.New("dpopProof is required")
	}
	if payload.AgentToken == "" {
		return PaymentResult{}, errors.New("agentToken is required for payment authorization")
	}

	// Step 1: parse CB4A access token, verify CDP signature.
	var claims cb4a.CB4ATokenClaims
	if _, err := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods([]string{"ES256"}),
	).ParseWithClaims(payload.CB4AToken, &claims, func(_ *jwt.Token) (any, error) {
		return g.cdpPub, nil
	}); err != nil {
		return PaymentResult{}, fmt.Errorf("invalid CB4A token: %w", err)
	}

	// Step 2: confirm scope covers the required payment.
	if err := g.checkScope(claims.Scope); err != nil {
		return PaymentResult{}, err
	}

	// Step 3: verify DPoP proof (htm/htu/ath/exp/jti replay via CDP).
	if err := g.cdp.SimulateAPICall(payload.CB4AToken, payload.DPoPProof, method, uri); err != nil {
		return PaymentResult{}, fmt.Errorf("DPoP verification failed: %w", err)
	}

	// Step 4: validate WIMSE AgentToken, confirm identity matches CB4A claim.
	va, err := g.agentValidator.Validate(payload.AgentToken)
	if err != nil {
		return PaymentResult{}, fmt.Errorf("invalid AgentToken: %w", err)
	}
	if va.Claims.Subject != claims.AgentSVID {
		return PaymentResult{}, fmt.Errorf("AgentToken sub %q != CB4A agent_svid %q",
			va.Claims.Subject, claims.AgentSVID)
	}

	return PaymentResult{
		AgentSVID: claims.AgentSVID,
		Scope:     claims.Scope,
		Asset:     g.asset,
		Amount:    g.amount,
		Resource:  uri,
	}, nil
}

// checkScope verifies that the CB4A scope covers the required payment.
// Expected scope format: "payment:<asset>:<amount>"
func (g *PaymentGateway) checkScope(scope string) error {
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 || parts[0] != "payment" {
		return fmt.Errorf("scope %q is not a payment scope (expected payment:<asset>:<amount>)", scope)
	}
	if parts[1] != g.asset {
		return fmt.Errorf("payment asset %q does not match required %q", parts[1], g.asset)
	}
	if parts[2] != g.amount {
		return fmt.Errorf("payment amount %q does not match required %q", parts[2], g.amount)
	}
	return nil
}
