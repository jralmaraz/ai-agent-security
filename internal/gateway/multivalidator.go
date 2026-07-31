package gateway

import (
	"fmt"

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
