package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// AgentChain is an ordered sequence of compact AgentToken JWTs representing
// a multi-hop delegation chain. The wire format is:
//
//	AT-1~AT-2~...~AT-N
//
// where AT-1 is the originating orchestrator token (chain_depth=0) and AT-N
// is the most recent delegation.
type AgentChain []string

// ParseChain splits the wire-format chain string into an AgentChain.
// Returns an error if the string is empty.
func ParseChain(s string) (AgentChain, error) {
	if s == "" {
		return nil, errors.New("empty chain string")
	}
	parts := strings.Split(s, "~")
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("empty token at position %d", i)
		}
	}
	return AgentChain(parts), nil
}

// String returns the wire-format chain string (AT-1~AT-2~...~AT-N).
func (c AgentChain) String() string {
	return strings.Join(c, "~")
}

// Len returns the number of tokens in the chain.
func (c AgentChain) Len() int { return len(c) }

// Extend appends a new token to the chain and returns the new chain.
// The original chain is not modified.
func (c AgentChain) Extend(token string) (AgentChain, error) {
	if token == "" {
		return nil, errors.New("cannot extend with empty token")
	}
	next := make(AgentChain, len(c)+1)
	copy(next, c)
	next[len(c)] = token
	return next, nil
}

// Hash returns the base64url-encoded SHA-256 digest of the wire-format chain.
// This is used as the chain_hash claim in AgentProofTokens.
func (c AgentChain) Hash() string {
	h := sha256.Sum256([]byte(c.String()))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Validate validates every token in the chain using the provided validators map,
// keyed by issuer ID.
//
// Validation rules:
//   - The first token must have chain_depth == 0.
//   - Each subsequent token must have chain_depth == previous + 1.
//   - Each token is validated by the validator whose issuerID matches the iss claim
//     (extracted via an unverified parse of the payload).
//   - All tokens must be individually valid (sig, exp, typ).
func (c AgentChain) Validate(validators map[string]*AgentValidator) ([]*ValidatedAgent, error) {
	if len(c) == 0 {
		return nil, errors.New("empty chain")
	}
	results := make([]*ValidatedAgent, 0, len(c))
	for i, tok := range c {
		issuer, err := peekIssuer(tok)
		if err != nil {
			return nil, fmt.Errorf("chain[%d]: peek issuer: %w", i, err)
		}
		v, ok := validators[issuer]
		if !ok {
			return nil, fmt.Errorf("chain[%d]: no validator for issuer %q", i, issuer)
		}
		va, err := v.Validate(tok)
		if err != nil {
			return nil, fmt.Errorf("chain[%d]: %w", i, err)
		}
		if va.Claims.ChainDepth != i {
			return nil, fmt.Errorf("chain[%d]: expected chain_depth %d, got %d", i, i, va.Claims.ChainDepth)
		}
		results = append(results, va)
	}
	return results, nil
}

// peekIssuer extracts the "iss" claim from a JWT without verifying the signature.
func peekIssuer(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := jsonUnmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	if claims.Iss == "" {
		return "", errors.New("missing iss claim")
	}
	return claims.Iss, nil
}
