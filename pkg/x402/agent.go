package x402

import (
	"fmt"

	"github.com/jralmaraz/ai-agent-security/pkg/cb4a"
)

// PayingAgent holds a CB4A minted credential and a WIMSE AgentToken,
// enabling an agent to construct x402 payment payloads.
//
// The minted credential is DPoP-bound: a fresh DPoP proof is generated
// per call to BuildPayload, so each payment authorization is unique
// and cannot be replayed.
type PayingAgent struct {
	minted     *cb4a.MintedCredential
	agentToken string
}

// NewPayingAgent creates a PayingAgent.
//
//   - minted: a CB4A credential with scope payment:ASSET:AMOUNT, freshly minted by the CDP
//   - agentToken: the payer's WIMSE AgentToken (agent+jwt); sub must match minted.AgentSVID
func NewPayingAgent(minted *cb4a.MintedCredential, agentToken string) *PayingAgent {
	return &PayingAgent{minted: minted, agentToken: agentToken}
}

// BuildPayload constructs an x402 PaymentPayload for the given HTTP method and URI.
// A fresh DPoP proof is generated per call — never reuse a PaymentPayload.
func (a *PayingAgent) BuildPayload(method, uri string) (PaymentPayload, error) {
	proof, err := cb4a.GenerateDPoPProof(a.minted, method, uri)
	if err != nil {
		return PaymentPayload{}, fmt.Errorf("generate DPoP proof: %w", err)
	}
	return PaymentPayload{
		X402Version: X402Version,
		Scheme:      SchemeCB4ADPOP,
		Network:     NetworkWIMSE,
		CB4AToken:   a.minted.Token,
		DPoPProof:   proof,
		AgentToken:  a.agentToken,
	}, nil
}
