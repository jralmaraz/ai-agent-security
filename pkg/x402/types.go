// Package x402 implements the x402 HTTP payment protocol (https://x402.org)
// using CB4A-DPoP credentials as the payment authorization mechanism.
//
// Instead of EVM wallet signatures, a paying agent presents a CB4A access
// token (DPoP-bound, scope=payment:ASSET:AMOUNT) plus a WIMSE AgentToken
// that proves the cryptographic identity of the paying entity.
//
// Protocol overview:
//
//	1. Agent calls API → server returns 402 + PaymentRequired
//	2. Agent requests spending authority from CB4A PDP
//	3. PDP approves (auto or HITL) → CDP mints DPoP-bound payment credential
//	4. Agent builds PaymentPayload and retries → 200 OK
package x402

// X402Version is the protocol version supported by this implementation.
const X402Version = 1

// SchemeCB4ADPOP is the payment scheme identifier used in this implementation.
// An x402 server that accepts CB4A-DPoP payments advertises this scheme.
const SchemeCB4ADPOP = "cb4a-dpop"

// NetworkAgentSecurity is the network identifier for the AI Agent Security PoC.
const NetworkWIMSE = "ai-agent-security"

// PaymentRequired is the body of an HTTP 402 Payment Required response.
// It describes the payment methods the server accepts.
type PaymentRequired struct {
	X402Version int             `json:"x402Version"`
	Accepts     []PaymentMethod `json:"accepts"`
	Resource    string          `json:"resource"`
	Error       string          `json:"error,omitempty"`
}

// PaymentMethod describes one accepted payment scheme and amount.
type PaymentMethod struct {
	Scheme  string `json:"scheme"`  // SchemeCB4ADPOP
	Network string `json:"network"` // NetworkWIMSE
	Asset   string `json:"asset"`   // e.g. "AGENT_CREDIT"
	Amount  string `json:"amount"`  // required amount
}

// PaymentPayload is sent by the paying agent to authorize a payment.
// It is typically base64-encoded and included in an X-Payment header
// on the retry request after receiving a 402.
type PaymentPayload struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
	// CB4AToken is a DPoP-bound CB4A access token with scope payment:ASSET:AMOUNT.
	// Signed by the CB4A CDP, proves the PDP authorized this payment.
	CB4AToken string `json:"cb4aToken"`
	// DPoPProof is a per-request DPoP proof JWT (RFC 9449) binding the CB4A token
	// to this exact HTTP method + URI. Generated fresh for every payment attempt.
	DPoPProof string `json:"dpopProof"`
	// AgentToken is the WIMSE AgentToken (agent+jwt) identifying the paying agent.
	// Provides cryptographic proof of the payer's SPIFFE identity.
	// The AgentToken.sub must match the CB4AToken.agent_svid claim.
	AgentToken string `json:"agentToken"`
}

// PaymentResult is returned by PaymentGateway.Verify after successful verification.
type PaymentResult struct {
	AgentSVID string // paying agent's SPIFFE identity (from AgentToken.sub)
	Asset     string // asset type (e.g. "AGENT_CREDIT")
	Amount    string // authorized payment amount
	Scope     string // full CB4A scope (e.g. "payment:AGENT_CREDIT:100")
	Resource  string // target resource URI
}
