package webauthn_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/jralmaraz/ai-agent-security/pkg/webauthn"
)

func mustRegister(t *testing.T) *webauthn.Credential {
	t.Helper()
	c, err := webauthn.Register("alice@example.com")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	return c
}

func TestRegisterCreatesCredential(t *testing.T) {
	c, err := webauthn.Register("alice@example.com")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.ID == "" {
		t.Error("Credential.ID is empty")
	}
	if c.PublicKey == nil {
		t.Error("Credential.PublicKey is nil")
	}
	if c.UserID != "alice@example.com" {
		t.Errorf("UserID: got %q, want %q", c.UserID, "alice@example.com")
	}
}

func TestRegisterEmptyUserID(t *testing.T) {
	_, err := webauthn.Register("")
	if err == nil {
		t.Error("expected error for empty userID")
	}
}

func TestAssertionRoundTrip(t *testing.T) {
	c := mustRegister(t)
	challenge := []byte("test-challenge-1234")
	assertion, err := c.MakeAssertion(challenge)
	if err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}
	if assertion == "" {
		t.Fatal("assertion is empty")
	}
	if err := webauthn.VerifyAssertion(c.PublicKey, challenge, assertion); err != nil {
		t.Errorf("VerifyAssertion: %v", err)
	}
}

func TestAssertionWrongKey(t *testing.T) {
	c := mustRegister(t)
	challenge := []byte("test-challenge")
	assertion, err := c.MakeAssertion(challenge)
	if err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}

	// Generate a different key pair and try to verify with it.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	if err := webauthn.VerifyAssertion(&wrongKey.PublicKey, challenge, assertion); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestAssertionTamperedChallenge(t *testing.T) {
	c := mustRegister(t)
	challenge := []byte("original-challenge")
	assertion, err := c.MakeAssertion(challenge)
	if err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}
	if err := webauthn.VerifyAssertion(c.PublicKey, []byte("tampered-challenge"), assertion); err == nil {
		t.Error("expected verification failure with tampered challenge")
	}
}

func TestPRFIsDeterministic(t *testing.T) {
	c := mustRegister(t)
	input := []byte("context-label")
	out1 := c.PRF(input)
	out2 := c.PRF(input)
	if !bytes.Equal(out1, out2) {
		t.Error("PRF is not deterministic for the same input")
	}
	if len(out1) != 32 {
		t.Errorf("PRF output length: got %d, want 32", len(out1))
	}
}

func TestPRFDiffersForDifferentInputs(t *testing.T) {
	c := mustRegister(t)
	out1 := c.PRF([]byte("input-a"))
	out2 := c.PRF([]byte("input-b"))
	if bytes.Equal(out1, out2) {
		t.Error("PRF should differ for different inputs")
	}
}

func TestPRFDiffersAcrossCredentials(t *testing.T) {
	c1 := mustRegister(t)
	c2 := mustRegister(t)
	input := []byte("shared-context")
	if bytes.Equal(c1.PRF(input), c2.PRF(input)) {
		t.Error("PRF output should differ across credentials for the same input")
	}
}
