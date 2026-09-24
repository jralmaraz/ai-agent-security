package ssfreceiver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/ai-agent-security/pkg/ssfreceiver"
)

// buildSET creates a minimal SET JWT (unsigned, for testing only).
func buildSET(jti string, events map[string]any) string {
	evJSON := make(map[string]json.RawMessage, len(events))
	for k, v := range events {
		b, _ := json.Marshal(v)
		evJSON[k] = json.RawMessage(b)
	}

	type setClaims struct {
		jwt.RegisteredClaims
		Events map[string]json.RawMessage `json:"events"`
	}
	claims := setClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:     jti,
			Issuer: "https://idp.example",
		},
		Events: evJSON,
	}
	// Use an unsigned token (alg=none) — matches ParseUnverified in receiver.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	return s
}

func postSET(t *testing.T, h http.Handler, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ssf/events", strings.NewReader(tok))
	req.Header.Set("Content-Type", "application/secevent+jwt")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestReceiver_HappyPath(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	called := false
	r.On(ssfreceiver.EventTypeSessionRevoked, func(set ssfreceiver.SET) {
		called = true
		if set.JTI != "jti-001" {
			t.Errorf("want JTI jti-001, got %q", set.JTI)
		}
	})

	tok := buildSET("jti-001", map[string]any{
		ssfreceiver.EventTypeSessionRevoked: map[string]any{
			"subject": map[string]any{"format": "spiffe", "sub": "spiffe://example/agent"},
		},
	})

	rr := postSET(t, r, tok)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rr.Code, rr.Body)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestReceiver_DuplicateJTI(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	tok := buildSET("jti-dup", map[string]any{
		ssfreceiver.EventTypeSessionRevoked: map[string]any{},
	})

	rr1 := postSET(t, r, tok)
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("first: want 202, got %d", rr1.Code)
	}
	rr2 := postSET(t, r, tok)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("second: want 409, got %d", rr2.Code)
	}
}

func TestReceiver_WrongContentType(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	req := httptest.NewRequest(http.MethodPost, "/ssf/events", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("want 415, got %d", rr.Code)
	}
}

func TestReceiver_NoHandlerForEvent(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	// No handler registered — should still return 202.
	tok := buildSET("jti-no-handler", map[string]any{
		ssfreceiver.EventTypeTokenClaimsChange: map[string]any{},
	})
	rr := postSET(t, r, tok)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", rr.Code)
	}
}

func TestAgentRemediation_IsRevoked(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	ar := ssfreceiver.NewAgentRemediation(r)

	const agentSub = "spiffe://example.org/agent/worker"
	if ar.IsRevoked(agentSub) {
		t.Fatal("agent should not be revoked before event")
	}

	tok := buildSET("jti-revoke-001", map[string]any{
		ssfreceiver.EventTypeSessionRevoked: map[string]any{
			"subject": map[string]any{
				"format": "spiffe",
				"sub":    agentSub,
			},
		},
	})
	rr := postSET(t, r, tok)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rr.Code, rr.Body)
	}

	if !ar.IsRevoked(agentSub) {
		t.Error("agent should be revoked after session-revoked event")
	}
	_, ok := ar.RevokedSince(agentSub)
	if !ok {
		t.Error("RevokedSince should return true")
	}
}

func TestAgentRemediation_AltURIField(t *testing.T) {
	// Some transmitters use "uri" instead of "sub" in the subject identifier.
	r := ssfreceiver.NewReceiver()
	ar := ssfreceiver.NewAgentRemediation(r)

	const agentSub = "spiffe://example.org/agent/alt"
	tok := buildSET("jti-uri-field", map[string]any{
		ssfreceiver.EventTypeSessionRevoked: map[string]any{
			"subject": map[string]any{
				"format": "uri",
				"uri":    agentSub,
			},
		},
	})
	postSET(t, r, tok)
	if !ar.IsRevoked(agentSub) {
		t.Error("agent should be revoked using uri field")
	}
}

func TestAgentRemediation_NotRevokedAfterDifferentEvent(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	ar := ssfreceiver.NewAgentRemediation(r)

	const agentSub = "spiffe://example.org/agent/other"
	// Send a token-claims-change, not session-revoked.
	tok := buildSET("jti-claims-change", map[string]any{
		ssfreceiver.EventTypeTokenClaimsChange: map[string]any{
			"subject": map[string]any{"sub": agentSub},
		},
	})
	postSET(t, r, tok)
	if ar.IsRevoked(agentSub) {
		t.Error("token-claims-change must not revoke the agent")
	}
}

func TestAgentRemediation_RevokedSince_Timing(t *testing.T) {
	r := ssfreceiver.NewReceiver()
	ar := ssfreceiver.NewAgentRemediation(r)

	const agentSub = "spiffe://example.org/agent/timing"
	before := time.Now()
	tok := buildSET("jti-timing", map[string]any{
		ssfreceiver.EventTypeSessionRevoked: map[string]any{
			"subject": map[string]any{"format": "spiffe", "sub": agentSub},
		},
	})
	postSET(t, r, tok)
	after := time.Now()

	ts, ok := ar.RevokedSince(agentSub)
	if !ok {
		t.Fatal("agent should be revoked")
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("revocation timestamp %v not between %v and %v", ts, before, after)
	}
}
