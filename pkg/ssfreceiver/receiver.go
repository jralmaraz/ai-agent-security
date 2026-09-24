// Package ssfreceiver implements the receiver side of the OpenID Shared
// Signals Framework (SSF) for the WIMSE agent gateway.
//
// Inbound Security Event Tokens (SETs) are delivered via HTTP push
// (webhook) to POST /ssf/events.  Each SET is a JWT containing an
// "events" claim that maps CAEP event-type URIs to their payloads.
// Registered handlers are dispatched synchronously before the 202 is
// returned; keep them fast.
//
// Signature verification is deliberately skipped in this PoC — trust is
// established via the mTLS transport layer.  Production deployments MUST
// verify the SET signature against the transmitter's JWKS endpoint.
package ssfreceiver

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// CAEP event-type URIs (OpenID CAEP 1.0).
const (
	EventTypeSessionRevoked    = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTypeTokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventTypeCredentialChange  = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
)

const contentTypeSET = "application/secevent+jwt"

// SET is a decoded Security Event Token delivered by an SSF transmitter.
type SET struct {
	JTI      string
	Issuer   string
	IssuedAt int64
	// Events maps CAEP event-type URI → raw JSON payload.
	Events map[string]json.RawMessage
}

// Handler is invoked for each event-type present in an incoming SET.
type Handler func(set SET)

type setClaims struct {
	jwt.RegisteredClaims
	Events map[string]json.RawMessage `json:"events"`
}

// Receiver accepts inbound SSF SET pushes and dispatches them to
// handlers registered with On.
type Receiver struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
	jtiSeen  map[string]struct{}
}

// NewReceiver creates a Receiver ready to accept registrations.
func NewReceiver() *Receiver {
	return &Receiver{
		handlers: make(map[string][]Handler),
		jtiSeen:  make(map[string]struct{}),
	}
}

// On registers h to be called whenever a SET containing eventType arrives.
func (r *Receiver) On(eventType string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[eventType] = append(r.handlers[eventType], h)
}

// ServeHTTP handles an inbound SET push (POST, Content-Type: application/secevent+jwt).
// Returns 202 on success, 400 on parse error, 409 on duplicate JTI, 415 on wrong content type.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ct := req.Header.Get("Content-Type")
	if ct != contentTypeSET {
		http.Error(w, "Content-Type must be "+contentTypeSET, http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<16)) // 64 KB cap
	if err != nil || len(body) == 0 {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Production MUST verify SET signature against transmitter JWKS.
	// PoC trusts via mTLS transport; ParseUnverified is intentional here.
	p := jwt.NewParser()
	var claims setClaims
	token, _, err := p.ParseUnverified(string(body), &claims)
	if err != nil || token == nil {
		http.Error(w, "invalid SET JWT: "+err.Error(), http.StatusBadRequest)
		return
	}

	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}
	set := SET{
		JTI:      claims.ID,
		Issuer:   claims.Issuer,
		IssuedAt: issuedAt,
		Events:   claims.Events,
	}

	if set.JTI == "" {
		http.Error(w, "SET missing jti", http.StatusBadRequest)
		return
	}

	r.mu.Lock()
	if _, seen := r.jtiSeen[set.JTI]; seen {
		r.mu.Unlock()
		http.Error(w, "duplicate SET jti", http.StatusConflict)
		return
	}
	r.jtiSeen[set.JTI] = struct{}{}
	r.mu.Unlock()

	r.dispatch(set)

	w.WriteHeader(http.StatusAccepted)
}

func (r *Receiver) dispatch(set SET) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for eventType := range set.Events {
		for _, h := range r.handlers[eventType] {
			h(set)
		}
	}
}
