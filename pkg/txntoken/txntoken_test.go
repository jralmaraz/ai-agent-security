package txntoken_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/txntoken"
)

const (
	ttsIssuer = "https://tts.agent-mesh.example"
	userSub   = "user@example.com"
)

func newIssuer(t *testing.T) (*txntoken.Issuer, *keys.ECKeyPair) {
	t.Helper()
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("GenerateECKeyPair: %v", err)
	}
	return txntoken.NewIssuer(ttsIssuer, kp.Private, time.Hour), kp
}

func defaultOpts() txntoken.IssueOptions {
	return txntoken.IssueOptions{
		Subject:   userSub,
		Audiences: []string{"https://api.agent-mesh.example"},
		ReqCtx: &txntoken.RequestContext{
			ReqIP: "10.0.0.1",
			ReqWL: "spiffe://agent-mesh.example/agents/orchestrator",
		},
	}
}

func TestTxnToken_HappyPath(t *testing.T) {
	issuer, kp := newIssuer(t)
	tok, err := issuer.Issue(defaultOpts())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != userSub {
		t.Errorf("subject: want %q got %q", userSub, claims.Subject)
	}
	if claims.Txn == "" {
		t.Error("expected non-empty txn claim")
	}
	if claims.ReqCtx == nil || claims.ReqCtx.ReqWL == "" {
		t.Error("expected rctx.req_wl to be set")
	}
}

func TestTxnToken_TypHeader(t *testing.T) {
	issuer, _ := newIssuer(t)
	tok, _ := issuer.Issue(defaultOpts())

	p := jwt.NewParser()
	var c txntoken.Claims
	parsed, _, err := p.ParseUnverified(tok, &c)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	typ, _ := parsed.Header["typ"].(string)
	if typ != "txntoken+jwt" {
		t.Errorf("typ: want %q got %q", "txntoken+jwt", typ)
	}
}

func TestTxnToken_TxnIDPropagated(t *testing.T) {
	issuer, kp := newIssuer(t)
	opts := defaultOpts()
	opts.TxnID = "fixed-txn-id-for-test"
	tok, _ := issuer.Issue(opts)

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Txn != opts.TxnID {
		t.Errorf("txn: want %q got %q", opts.TxnID, claims.Txn)
	}
}

func TestTxnToken_AzDetails(t *testing.T) {
	issuer, kp := newIssuer(t)
	opts := defaultOpts()
	opts.AzDetails = []txntoken.AuthorizationDetail{
		{Type: "ai-action", Claims: map[string]string{"scope": "read:orders", "budget": "500"}},
	}
	tok, _ := issuer.Issue(opts)

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(claims.AzDetails) != 1 || claims.AzDetails[0].Type != "ai-action" {
		t.Errorf("azd not round-tripped: %+v", claims.AzDetails)
	}
}

func TestTxnToken_WrongKey(t *testing.T) {
	issuer, _ := newIssuer(t)
	_, otherKP := newIssuer(t)
	tok, _ := issuer.Issue(defaultOpts())

	v := txntoken.NewValidator(ttsIssuer, otherKP.Public)
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("expected error with wrong key")
	}
}

func TestTxnToken_Expired(t *testing.T) {
	issuer, kp := newIssuer(t)
	opts := defaultOpts()
	opts.TTL = -time.Second
	tok, _ := issuer.Issue(opts)

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestTxnToken_IssuerMismatch(t *testing.T) {
	issuer, kp := newIssuer(t)
	tok, _ := issuer.Issue(defaultOpts())

	v := txntoken.NewValidator("https://other-tts.example", kp.Public)
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
}

func TestTxnToken_MissingSubject(t *testing.T) {
	issuer, _ := newIssuer(t)
	opts := defaultOpts()
	opts.Subject = ""
	if _, err := issuer.Issue(opts); err == nil {
		t.Fatal("expected error for missing subject")
	}
}

func TestTxnToken_MissingAudience(t *testing.T) {
	issuer, _ := newIssuer(t)
	opts := defaultOpts()
	opts.Audiences = nil
	if _, err := issuer.Issue(opts); err == nil {
		t.Fatal("expected error for missing audience")
	}
}

func TestTxnToken_Hash(t *testing.T) {
	h1 := txntoken.Hash("some.jwt.token")
	h2 := txntoken.Hash("some.jwt.token")
	if h1 != h2 {
		t.Error("Hash is not deterministic")
	}
	if h1 == "" {
		t.Error("Hash returned empty string")
	}
	h3 := txntoken.Hash("other.jwt.token")
	if h1 == h3 {
		t.Error("different inputs produced same hash")
	}
}

func TestTxnToken_EmptyString(t *testing.T) {
	_, kp := newIssuer(t)
	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	if _, err := v.Validate(""); err == nil {
		t.Fatal("expected error for empty token string")
	}
}

func TestTxnToken_ActClaim(t *testing.T) {
	// RFC 8693 §4.1: sub = user, act.sub = entry-point agent SPIFFE ID.
	issuer, kp := newIssuer(t)
	opts := defaultOpts()
	opts.Actor = &txntoken.ActorClaims{
		Sub: "spiffe://agent-mesh.example/agents/orchestrator",
	}
	tok, err := issuer.Issue(opts)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Act == nil {
		t.Fatal("expected act claim to be present")
	}
	if claims.Act.Sub != opts.Actor.Sub {
		t.Errorf("act.sub: want %q got %q", opts.Actor.Sub, claims.Act.Sub)
	}
	if claims.Act.Act != nil {
		t.Error("expected no nested act for single-hop chain")
	}
}

func TestTxnToken_ActChain(t *testing.T) {
	// RFC 8693 §4.1: nested act represents prior actors in a multi-hop chain.
	// Outermost act = current actor; deepest act = original actor (informational only).
	issuer, kp := newIssuer(t)
	opts := defaultOpts()
	opts.Actor = &txntoken.ActorClaims{
		Sub: "spiffe://agent-mesh.example/agents/orchestrator",
		Act: &txntoken.ActorClaims{
			Sub: "spiffe://agent-mesh.example/gateway",
		},
	}
	tok, err := issuer.Issue(opts)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	v := txntoken.NewValidator(ttsIssuer, kp.Public)
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Act == nil || claims.Act.Act == nil {
		t.Fatal("expected nested act claim for multi-hop chain")
	}
	if claims.Act.Sub != "spiffe://agent-mesh.example/agents/orchestrator" {
		t.Errorf("current actor sub: got %q", claims.Act.Sub)
	}
	if claims.Act.Act.Sub != "spiffe://agent-mesh.example/gateway" {
		t.Errorf("prior actor sub: got %q", claims.Act.Act.Sub)
	}
}
