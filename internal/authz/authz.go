// Package authz provides fine-grained authorization for agent workloads.
//
// The Authorizer interface abstracts over authorization back-ends.
// InMemoryAuthorizer is suitable for tests and local development.
// OpenFGAAuthorizer delegates to an OpenFGA server (Zanzibar-style).
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/openfga/go-sdk/client"
)

// Action represents a permission the caller wants to exercise.
type Action string

const (
	ActionCall  Action = "can_call"
	ActionRead  Action = "can_read"
	ActionWrite Action = "can_write"
)

// Decision is the result of an authorization check.
type Decision struct {
	// Allowed is true when the action is permitted.
	Allowed bool
	// Reason is a human-readable explanation (useful for audit logs).
	Reason string

	// Pending is true when access is denied but can be requested for approval.
	// COAZ-MCP Binding 1.0 / AuthZEN AARP 1.0 §4 — third outcome.
	Pending bool
	// ApprovalEndpoint is the URL where the subject can submit an approval request.
	// Only set when Pending is true.
	ApprovalEndpoint string
}

// Request is the input to an authorization check.
type Request struct {
	// Subject is the caller's SPIFFE URI (from AgentToken.Sub).
	Subject string
	// Object is the resource being accessed (e.g. "tool:weather-api").
	Object string
	// Action is the permission being requested.
	Action Action

	// ToolParams carries the MCP tool call parameters for parameter-level authorization.
	// COAZ-MCP Binding 1.0: the AuthZEN context element is populated from these.
	// Authorizers may use these to enforce parameter-level policy (e.g. restrict SQL
	// QUERY bodies, limit file paths, cap pagination limits).
	ToolParams map[string]any
}

// Authorizer checks whether an agent is allowed to perform an action.
type Authorizer interface {
	Authorize(ctx context.Context, req Request) (Decision, error)
}

// ── InMemoryAuthorizer ────────────────────────────────────────────────────────

// rule is an entry in the in-memory policy table.
type rule struct {
	subject string
	object  string
	action  Action
}

// InMemoryAuthorizer is a simple policy store backed by a slice of allow-rules.
// It supports wildcard subjects ("*") and action inheritance:
// can_call implies can_read; can_write implies can_read.
type InMemoryAuthorizer struct {
	mu    sync.RWMutex
	rules []rule
}

// NewInMemoryAuthorizer creates an empty authorizer with no rules.
func NewInMemoryAuthorizer() *InMemoryAuthorizer {
	return &InMemoryAuthorizer{}
}

// Allow adds a rule granting subject the given action on object.
// subject may be "*" to match all agents.
func (a *InMemoryAuthorizer) Allow(subject, object string, action Action) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rules = append(a.rules, rule{subject: subject, object: object, action: action})
}

// Authorize checks whether req is permitted by any stored rule,
// applying the action-inheritance model:
//   - can_call → also satisfies can_read
//   - can_write → also satisfies can_read
func (a *InMemoryAuthorizer) Authorize(_ context.Context, req Request) (Decision, error) {
	if req.Subject == "" || req.Object == "" {
		return Decision{}, errors.New("subject and object are required")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, r := range a.rules {
		if !matchSubject(r.subject, req.Subject) {
			continue
		}
		if r.object != req.Object {
			continue
		}
		if actionSatisfies(r.action, req.Action) {
			return Decision{
				Allowed: true,
				Reason:  fmt.Sprintf("rule: %s %s %s", r.subject, r.action, r.object),
			}, nil
		}
	}
	return Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("no rule permits %s → %s on %s", req.Subject, req.Action, req.Object),
	}, nil
}

// matchSubject returns true if ruleSubject == "*" or == subject.
func matchSubject(ruleSubject, subject string) bool {
	return ruleSubject == "*" || ruleSubject == subject
}

// actionSatisfies returns true when granted implies requested.
//
//	can_call  → can_call, can_read
//	can_write → can_write, can_read
//	can_read  → can_read
func actionSatisfies(granted, requested Action) bool {
	if granted == requested {
		return true
	}
	if requested == ActionRead && (granted == ActionCall || granted == ActionWrite) {
		return true
	}
	return false
}

// ── OpenFGAAuthorizer ─────────────────────────────────────────────────────────

// OpenFGAConfig holds the configuration for connecting to an OpenFGA server.
type OpenFGAConfig struct {
	// APIURL is the base URL of the OpenFGA server (e.g. "http://localhost:8080").
	APIURL string
	// StoreID is the OpenFGA store to query.
	StoreID string
	// AuthorizationModelID is the model to use for checks (empty = latest).
	AuthorizationModelID string
}

// OpenFGAAuthorizer delegates authorization checks to an OpenFGA server.
// It uses the OpenFGA relation-tuple model: subject has <action> on <object>.
type OpenFGAAuthorizer struct {
	c        *client.OpenFgaClient
	storeID  string
	modelID  string
}

// NewOpenFGAAuthorizer creates an authorizer connected to an OpenFGA server.
func NewOpenFGAAuthorizer(cfg OpenFGAConfig) (*OpenFGAAuthorizer, error) {
	if cfg.APIURL == "" || cfg.StoreID == "" {
		return nil, errors.New("APIURL and StoreID are required")
	}
	clientCfg := &client.ClientConfiguration{
		ApiUrl:  cfg.APIURL,
		StoreId: cfg.StoreID,
	}
	if cfg.AuthorizationModelID != "" {
		clientCfg.AuthorizationModelId = cfg.AuthorizationModelID
	}
	c, err := client.NewSdkClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("create OpenFGA client: %w", err)
	}
	return &OpenFGAAuthorizer{c: c, storeID: cfg.StoreID, modelID: cfg.AuthorizationModelID}, nil
}

// Authorize checks the OpenFGA store for a matching tuple.
// Subject is passed as the OpenFGA user object (type "agent"),
// Object is the resource (e.g. "tool:weather-api"),
// Action maps directly to the OpenFGA relation name (can_call, can_read, can_write).
func (a *OpenFGAAuthorizer) Authorize(ctx context.Context, req Request) (Decision, error) {
	if req.Subject == "" || req.Object == "" {
		return Decision{}, errors.New("subject and object are required")
	}

	// Convert subject to OpenFGA user format: "agent:<escaped-uri>"
	user := "agent:" + escapeURI(req.Subject)

	body := client.ClientCheckRequest{
		User:     user,
		Relation: string(req.Action),
		Object:   req.Object,
	}

	resp, err := a.c.Check(ctx).Body(body).Execute()
	if err != nil {
		return Decision{}, fmt.Errorf("OpenFGA check: %w", err)
	}

	allowed := resp.GetAllowed()
	reason := "OpenFGA: denied"
	if allowed {
		reason = "OpenFGA: allowed"
	}
	return Decision{Allowed: allowed, Reason: reason}, nil
}

// escapeURI replaces characters that are invalid in OpenFGA user IDs.
func escapeURI(uri string) string {
	return strings.NewReplacer("://", "_", "/", "_", ".", "-").Replace(uri)
}
