package identity

import (
	"errors"
	"sync"
	"time"
)

// JTIStore records proof-token JTIs to prevent replay attacks.
//
// The default InMemoryJTIStore is suitable for single-process deployments.
// For multi-replica deployments (Kubernetes, multi-cloud), replace with an
// etcd-, Redis-, or CockroachDB-backed implementation that shares state across
// all replicas. This is the distributed-consensus plug-in point: any store
// that serialises Record() across the cluster eliminates the replay window
// that exists between independent in-memory stores.
//
// Record must return ErrReplayed if the given JTI has already been seen, and
// must be safe for concurrent use.
type JTIStore interface {
	Record(jti string, exp time.Time) error
}

// ErrReplayed is returned by JTIStore.Record when a JTI has already been seen.
var ErrReplayed = errors.New("JTI already seen (replay attack)")

// InMemoryJTIStore is the default single-process replay store. It sweeps
// expired entries on each Record call, bounding memory to the number of
// live JTIs within their validity window (typically a few minutes at the
// configured proof TTL).
//
// Safety: a replayed-but-expired token is rejected by the JWT expiry check
// before Record is ever called, so evicting an expired JTI cannot reopen
// a replay window.
type InMemoryJTIStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // jti → expiry
}

// NewInMemoryJTIStore creates a new InMemoryJTIStore.
func NewInMemoryJTIStore() *InMemoryJTIStore {
	return &InMemoryJTIStore{seen: make(map[string]time.Time)}
}

// Record records a JTI and returns ErrReplayed if it has already been seen.
// Expired entries are swept before the check so memory stays bounded.
func (s *InMemoryJTIStore) Record(jti string, exp time.Time) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, expiry := range s.seen {
		if now.After(expiry) {
			delete(s.seen, id)
		}
	}
	if _, replayed := s.seen[jti]; replayed {
		return ErrReplayed
	}
	s.seen[jti] = exp
	return nil
}
