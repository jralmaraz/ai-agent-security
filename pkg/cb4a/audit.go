package cb4a

import (
	"sync"
	"time"
)

// EventType classifies audit events.
type EventType string

const (
	EventEnvelopeReceived EventType = "envelope_received"
	EventPolicyEvaluated  EventType = "policy_evaluated"
	EventApproved         EventType = "approved"
	EventDenied           EventType = "denied"
	EventCredentialMinted EventType = "credential_minted"
	EventAPICall          EventType = "api_call"
	EventReplayRejected   EventType = "replay_rejected"
)

// AuditEntry is a single immutable audit record.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     EventType `json:"event"`
	AgentSVID string    `json:"agent_svid"`
	Target    string    `json:"target"`
	Action    string    `json:"action"`
	Scope     string    `json:"scope"`
	Tier      int       `json:"tier,omitempty"`
	RequestID string    `json:"request_id"`
	Detail    string    `json:"detail,omitempty"`
	Success   bool      `json:"success"`
}

// AuditLog is an append-only, thread-safe audit trail.
//
// Append is fail-closed by contract: callers must treat a non-nil error as a
// hard failure and not proceed with credential issuance.  The in-memory
// implementation always returns nil; persistent backends may return errors.
type AuditLog struct {
	mu      sync.RWMutex
	entries []AuditEntry
}

// NewAuditLog creates an empty audit log.
func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

// Append adds an entry to the log.
func (l *AuditLog) Append(e AuditEntry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	l.mu.Lock()
	l.entries = append(l.entries, e)
	l.mu.Unlock()
	return nil
}

// Entries returns a snapshot copy of all audit entries.
func (l *AuditLog) Entries() []AuditEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Len returns the number of recorded entries.
func (l *AuditLog) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
