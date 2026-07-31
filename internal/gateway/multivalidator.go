package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/identity"
)

// validateWithAny tries every validator and returns the first success.
// Used to support multiple trusted IdPs at the gateway.
func validateWithAny(validators map[string]*identity.AgentValidator, token string) (*identity.ValidatedAgent, error) {
	var lastErr error
	for _, v := range validators {
		va, err := v.Validate(token)
		if err == nil {
			return va, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no validators configured")
}

// peekIssuer decodes the JWT payload without verifying the signature to extract "iss".
func peekIssuer(tokenStr string) (string, error) {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return "", errors.New("not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid JWT payload encoding")
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("invalid JWT payload JSON")
	}
	if claims.Issuer == "" {
		return "", errors.New("missing iss claim")
	}
	return claims.Issuer, nil
}
