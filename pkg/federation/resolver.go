package federation

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

// ResolvedEntity holds the verified public keys for an entity and when they expire.
type ResolvedEntity struct {
	JWKS      []keys.JWK
	ExpiresAt time.Time
}

// PublicKey returns the first EC P-256 public key from the resolved JWKS.
func (e *ResolvedEntity) PublicKey() (*ecdsa.PublicKey, error) {
	for i := range e.JWKS {
		pub, err := keys.JWKToPublicKey(&e.JWKS[i])
		if err == nil {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("no valid EC public key in resolved JWKS")
}

// Resolver resolves entity public keys via an OID-FED trust chain.
// Implementations must be safe for concurrent use.
type Resolver interface {
	Resolve(ctx context.Context, entityID string) (*ResolvedEntity, error)
}

// ---------- InMemoryResolver ----------

// InMemoryResolver resolves trust chains from pre-loaded JWTs.
// Suitable for WASM (no HTTP) and for tests.
type InMemoryResolver struct {
	mu            sync.RWMutex
	entityConfigs map[string]string // entityID → EC JWT
	subStatements map[string]string // subjectID → SS JWT
	trustAnchors  map[string]*ecdsa.PublicKey
	cache         sync.Map // entityID → *ResolvedEntity
}

// NewInMemoryResolver creates an empty registry.
func NewInMemoryResolver(trustAnchors map[string]*ecdsa.PublicKey) *InMemoryResolver {
	return &InMemoryResolver{
		entityConfigs: make(map[string]string),
		subStatements: make(map[string]string),
		trustAnchors:  trustAnchors,
	}
}

// RegisterEntityConfig stores a signed Entity Configuration JWT.
func (r *InMemoryResolver) RegisterEntityConfig(entityID, ecJWT string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entityConfigs[entityID] = ecJWT
	r.cache.Delete(entityID)
}

// RegisterSubordinateStatement stores a signed Subordinate Statement JWT.
func (r *InMemoryResolver) RegisterSubordinateStatement(subjectID, ssJWT string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subStatements[subjectID] = ssJWT
	r.cache.Delete(subjectID)
}

// Resolve resolves the public key for the given entity ID via the trust chain.
func (r *InMemoryResolver) Resolve(_ context.Context, entityID string) (*ResolvedEntity, error) {
	if v, ok := r.cache.Load(entityID); ok {
		e := v.(*ResolvedEntity)
		if time.Now().Before(e.ExpiresAt) {
			return e, nil
		}
		r.cache.Delete(entityID)
	}

	r.mu.RLock()
	ecJWT, hasEC := r.entityConfigs[entityID]
	ssJWT, hasSS := r.subStatements[entityID]
	r.mu.RUnlock()

	if !hasEC {
		return nil, fmt.Errorf("no entity configuration registered for %q", entityID)
	}
	if !hasSS {
		return nil, fmt.Errorf("no subordinate statement registered for %q", entityID)
	}

	leafEC, err := ParseEntityConfiguration(ecJWT)
	if err != nil {
		return nil, fmt.Errorf("parse entity configuration for %q: %w", entityID, err)
	}

	var verifiedSS *SubordinateStatement
	for _, hint := range leafEC.AuthorityHints {
		anchorPub, ok := r.trustAnchors[hint]
		if !ok {
			continue
		}
		ss, err := VerifySubordinateStatement(ssJWT, anchorPub)
		if err != nil {
			continue
		}
		if ss.Subject != entityID {
			continue
		}
		verifiedSS = ss
		break
	}
	if verifiedSS == nil {
		return nil, fmt.Errorf("no trusted authority verified entity %q (hints: %v)", entityID, leafEC.AuthorityHints)
	}

	if len(verifiedSS.JWKS.Keys) == 0 {
		return nil, fmt.Errorf("subordinate statement for %q has no JWKS", entityID)
	}
	leafPub, err := keys.JWKToPublicKey(&verifiedSS.JWKS.Keys[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf key from SS: %w", err)
	}
	if _, err := VerifyEntityConfiguration(ecJWT, leafPub); err != nil {
		return nil, fmt.Errorf("entity configuration for %q not signed by its certified key: %w", entityID, err)
	}

	exp := time.Unix(verifiedSS.ExpiresAt, 0)
	if ecExp := time.Unix(leafEC.ExpiresAt, 0); ecExp.Before(exp) {
		exp = ecExp
	}
	entity := &ResolvedEntity{JWKS: verifiedSS.JWKS.Keys, ExpiresAt: exp}
	r.cache.Store(entityID, entity)
	return entity, nil
}

// ---------- HTTPResolver ----------

// HTTPResolver resolves trust chains by fetching JWTs over HTTP.
// Not usable in WASM.
type HTTPResolver struct {
	TrustAnchors map[string]*ecdsa.PublicKey
	client       *http.Client
	cache        sync.Map
}

// NewHTTPResolver creates an HTTPResolver that trusts the given anchors.
func NewHTTPResolver(trustAnchors map[string]*ecdsa.PublicKey) *HTTPResolver {
	return &HTTPResolver{
		TrustAnchors: trustAnchors,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Resolve fetches and verifies the trust chain for entityID.
func (r *HTTPResolver) Resolve(ctx context.Context, entityID string) (*ResolvedEntity, error) {
	if v, ok := r.cache.Load(entityID); ok {
		e := v.(*ResolvedEntity)
		if time.Now().Before(e.ExpiresAt) {
			return e, nil
		}
		r.cache.Delete(entityID)
	}

	ecURL := stripTrailingSlash(entityID) + "/.well-known/openid-federation"
	ecJWT, err := r.fetchJWT(ctx, ecURL)
	if err != nil {
		return nil, fmt.Errorf("fetch entity configuration for %q: %w", entityID, err)
	}
	leafEC, err := ParseEntityConfiguration(ecJWT)
	if err != nil {
		return nil, fmt.Errorf("parse entity configuration for %q: %w", entityID, err)
	}

	for _, hint := range leafEC.AuthorityHints {
		anchorPub, ok := r.TrustAnchors[hint]
		if !ok {
			continue
		}
		ssURL := stripTrailingSlash(hint) + "/federation/fetch?sub=" + url.QueryEscape(entityID)
		ssJWT, err := r.fetchJWT(ctx, ssURL)
		if err != nil {
			continue
		}
		ss, err := VerifySubordinateStatement(ssJWT, anchorPub)
		if err != nil || ss.Subject != entityID {
			continue
		}
		if len(ss.JWKS.Keys) == 0 {
			continue
		}
		leafPub, err := keys.JWKToPublicKey(&ss.JWKS.Keys[0])
		if err != nil {
			continue
		}
		verifiedEC, err := VerifyEntityConfiguration(ecJWT, leafPub)
		if err != nil {
			continue
		}
		exp := time.Unix(ss.ExpiresAt, 0)
		if ecExp := time.Unix(verifiedEC.ExpiresAt, 0); ecExp.Before(exp) {
			exp = ecExp
		}
		entity := &ResolvedEntity{JWKS: ss.JWKS.Keys, ExpiresAt: exp}
		r.cache.Store(entityID, entity)
		return entity, nil
	}
	return nil, fmt.Errorf("no trust anchor found for entity %q (hints: %v)", entityID, leafEC.AuthorityHints)
}

func (r *HTTPResolver) fetchJWT(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/entity-statement+jwt")
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body from %s: %w", rawURL, err)
	}
	return string(b), nil
}

func stripTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
