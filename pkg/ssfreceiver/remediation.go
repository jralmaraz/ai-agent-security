package ssfreceiver

import (
	"encoding/json"
	"sync"
	"time"
)

// sessionRevokedPayload is the minimal CAEP session-revoked event body.
// The subject identifier is used to determine which agent to revoke.
type sessionRevokedPayload struct {
	Subject struct {
		Format string `json:"format"`
		Sub    string `json:"sub"`  // SPIFFE URI when format==="spiffe"
		URI    string `json:"uri"`  // alternative field used by some transmitters
	} `json:"subject"`
	Reason string `json:"reason,omitempty"`
}

// RevokedSet tracks which agent subjects have been revoked and when.
type RevokedSet struct {
	mu       sync.RWMutex
	subjects map[string]time.Time // SPIFFE URI → time of revocation
}

func newRevokedSet() *RevokedSet {
	return &RevokedSet{subjects: make(map[string]time.Time)}
}

func (rs *RevokedSet) revoke(subject string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.subjects[subject] = time.Now()
}

// IsRevoked returns true if subject has been revoked.
func (rs *RevokedSet) IsRevoked(subject string) bool {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	_, ok := rs.subjects[subject]
	return ok
}

// RevokedSince returns the time subject was revoked and true, or zero/false if not revoked.
func (rs *RevokedSet) RevokedSince(subject string) (time.Time, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	t, ok := rs.subjects[subject]
	return t, ok
}

// AgentRemediation wires a Receiver to a RevokedSet: when a session-revoked
// CAEP event arrives, the named agent subject is added to the revocation list.
// The gateway middleware calls IsRevoked on each request.
type AgentRemediation struct {
	Revoked  *RevokedSet
	receiver *Receiver
}

// NewAgentRemediation creates a remediation handler and registers it on r.
func NewAgentRemediation(r *Receiver) *AgentRemediation {
	ar := &AgentRemediation{
		Revoked:  newRevokedSet(),
		receiver: r,
	}
	r.On(EventTypeSessionRevoked, ar.handleSessionRevoked)
	return ar
}

// IsRevoked returns true if subject has received a session-revoked signal.
func (ar *AgentRemediation) IsRevoked(subject string) bool {
	return ar.Revoked.IsRevoked(subject)
}

// RevokedSince returns when the subject was revoked.
func (ar *AgentRemediation) RevokedSince(subject string) (time.Time, bool) {
	return ar.Revoked.RevokedSince(subject)
}

// Receiver returns the underlying Receiver so callers can register the
// HTTP endpoint (e.g. gateway.New wires it to POST /ssf/events).
func (ar *AgentRemediation) Receiver() *Receiver {
	return ar.receiver
}

func (ar *AgentRemediation) handleSessionRevoked(set SET) {
	raw, ok := set.Events[EventTypeSessionRevoked]
	if !ok {
		return
	}
	var payload sessionRevokedPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return
	}
	sub := payload.Subject.Sub
	if sub == "" {
		sub = payload.Subject.URI
	}
	if sub != "" {
		ar.Revoked.revoke(sub)
	}
}
