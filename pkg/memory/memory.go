// Package memory implements integrity-checked, agent-scoped persistent memory
// storage for AI agents, following:
//
//   - MITRE ATLAS AML.M0031 (Memory Hardening) — controls on how durable
//     agent state is created, modified, isolated, audited, and recovered.
//   - OWASP ASI06 (Memory and Context Poisoning) — runtime detection of
//     adversarial content injected into agent memory.
//
// # Architecture
//
// Every memory entry is scoped to an agent's SPIFFE URI (the sub claim from
// an AgentToken). The store enforces isolation: reads and deletes issued by
// agent A cannot access entries written by agent B, even if the underlying
// store is shared (e.g., a single pgvector table).
//
// # pgvector deployment note
//
// In production, pair this package with PostgreSQL + pgvector using row-level
// security (RLS):
//
//	CREATE POLICY agent_isolation ON agent_memories
//	  USING (agent_sub = current_setting('app.agent_sub'));
//
// The gateway middleware sets `SET LOCAL app.agent_sub = <token.sub>` before
// every query. Combined with the write-time validation in this package, this
// gives the full AML.M0031 isolation guarantee at the database layer.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// MemoryEntry is a single persistent memory record.
// The Integrity field is a SHA-256 hash of (AgentSub + Content + CreatedAt),
// computed at write time. Any modification to Content or AgentSub is detected
// when Read recomputes and compares the hash (AML.M0031 "modified" control).
type MemoryEntry struct {
	ID        string
	AgentSub  string // SPIFFE URI — isolation namespace
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
	Integrity string // hex SHA-256(AgentSub ‖ Content ‖ CreatedAt)
}

// ComputeIntegrity returns the expected SHA-256 hash for an entry.
// Inputs are deterministic so the same entry always produces the same hash.
func ComputeIntegrity(agentSub, content string, createdAt time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s", agentSub, content, createdAt.Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidationError is returned when a write is rejected by a detector.
type ValidationError struct {
	Detector string
	Reason   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("memory write rejected [%s]: %s", e.Detector, e.Reason)
}

// IntegrityError is returned when a read detects a tampered entry.
type IntegrityError struct {
	EntryID  string
	AgentSub string
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("integrity check failed: entry %q (agent %q)", e.EntryID, e.AgentSub)
}

// AuditRecord is an immutable log entry produced by every store operation.
// Implements AML.M0031 "audited" control.
type AuditRecord struct {
	At       time.Time
	AgentSub string
	EntryID  string
	Op       string // "write", "delete", "integrity_fail", "write_rejected"
	Detail   string
}

// MemoryStore is the interface for agent memory backends.
// All implementations MUST enforce agent-sub isolation.
type MemoryStore interface {
	Write(agentSub, id, content string) (*MemoryEntry, error)
	Read(agentSub string) ([]*MemoryEntry, error)
	Delete(agentSub, id string) error
	Audit(agentSub string) []AuditRecord
}

// injectionPatterns are lexical indicators of prompt injection attempts
// embedded in memory writes. Production systems add ML-based classifiers.
// Source: OWASP Agent Memory Guard detector taxonomy.
var injectionPatterns = []string{
	"ignore previous",
	"ignore all previous",
	"disregard your",
	"new instructions:",
	"system prompt:",
	"you are now",
	"act as if",
	"forget everything",
	"your true purpose",
	"<|system|>",
	"[system]",
	"<!-- system -->",
	"---\nsystem:",
}

const maxContentBytes = 50 * 1024 // 50 KB — configurable in production

// validateContent runs write-time detectors (AML.M0031 "created" control +
// OWASP ASI06 prompt-injection detector).
func validateContent(content string) error {
	if len(content) > maxContentBytes {
		return &ValidationError{
			Detector: "size_anomaly",
			Reason:   fmt.Sprintf("content is %d bytes, limit is %d", len(content), maxContentBytes),
		}
	}
	lower := strings.ToLower(content)
	for _, p := range injectionPatterns {
		if strings.Contains(lower, p) {
			return &ValidationError{
				Detector: "prompt_injection",
				Reason:   fmt.Sprintf("pattern %q detected in content", p),
			}
		}
	}
	return nil
}

// InMemoryStore is an in-process MemoryStore backed by a sync.Map,
// suitable for testing and single-process demos.
// For pgvector + RLS, see the deployment note in the package doc.
type InMemoryStore struct {
	mu      sync.RWMutex
	entries map[string][]*MemoryEntry // keyed by agentSub
	audit   map[string][]AuditRecord  // keyed by agentSub
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		entries: make(map[string][]*MemoryEntry),
		audit:   make(map[string][]AuditRecord),
	}
}

// Write validates and stores a memory entry for agentSub.
// Returns ValidationError if the content fails any detector.
func (s *InMemoryStore) Write(agentSub, id, content string) (*MemoryEntry, error) {
	if agentSub == "" {
		return nil, fmt.Errorf("agentSub must not be empty")
	}
	if id == "" {
		return nil, fmt.Errorf("id must not be empty")
	}

	if err := validateContent(content); err != nil {
		s.log(agentSub, id, "write_rejected", err.Error())
		return nil, err
	}

	now := time.Now().UTC()
	e := &MemoryEntry{
		ID:        id,
		AgentSub:  agentSub,
		Content:   content,
		CreatedAt: now,
		UpdatedAt: now,
		Integrity: ComputeIntegrity(agentSub, content, now),
	}

	s.mu.Lock()
	s.entries[agentSub] = append(s.entries[agentSub], e)
	s.mu.Unlock()

	s.log(agentSub, id, "write", "integrity="+e.Integrity[:8])
	return e, nil
}

// Read returns all memory entries for agentSub, verifying integrity on each.
// Returns IntegrityError on the first tampered entry (AML.M0031 "modified" control).
func (s *InMemoryStore) Read(agentSub string) ([]*MemoryEntry, error) {
	s.mu.RLock()
	stored := s.entries[agentSub]
	s.mu.RUnlock()

	results := make([]*MemoryEntry, 0, len(stored))
	for _, e := range stored {
		expected := ComputeIntegrity(e.AgentSub, e.Content, e.CreatedAt)
		if expected != e.Integrity {
			s.log(agentSub, e.ID, "integrity_fail", "sha256 mismatch on read")
			return nil, &IntegrityError{EntryID: e.ID, AgentSub: agentSub}
		}
		results = append(results, e)
	}
	return results, nil
}

// Delete removes an entry by ID for agentSub.
// Cross-agent deletes are silently denied (returns "not found")
// to prevent enumeration of other agents' entry IDs.
func (s *InMemoryStore) Delete(agentSub, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := s.entries[agentSub]
	for i, e := range entries {
		if e.ID == id {
			s.entries[agentSub] = append(entries[:i], entries[i+1:]...)
			s.logLocked(agentSub, id, "delete", "")
			return nil
		}
	}
	// Do NOT search other agents' maps — that would leak existence info.
	return fmt.Errorf("entry %q not found", id)
}

// Audit returns a snapshot of the write log for agentSub.
// Implements AML.M0031 "audited" control.
func (s *InMemoryStore) Audit(agentSub string) []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := s.audit[agentSub]
	out := make([]AuditRecord, len(recs))
	copy(out, recs)
	return out
}

func (s *InMemoryStore) log(agentSub, id, op, detail string) {
	s.mu.Lock()
	s.logLocked(agentSub, id, op, detail)
	s.mu.Unlock()
}

func (s *InMemoryStore) logLocked(agentSub, id, op, detail string) {
	s.audit[agentSub] = append(s.audit[agentSub], AuditRecord{
		At: time.Now().UTC(), AgentSub: agentSub,
		EntryID: id, Op: op, Detail: detail,
	})
}

// TamperForTesting mutates a stored entry's Content without updating
// Integrity, simulating a direct-database write that bypasses the store.
// Use only in tests to verify integrity checking.
func (s *InMemoryStore) TamperForTesting(agentSub, id, newContent string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries[agentSub] {
		if e.ID == id {
			e.Content = newContent // Integrity hash intentionally NOT updated.
			return true
		}
	}
	return false
}
