package keys_test

import (
	"encoding/json"
	"testing"

	"github.com/jralmaraz/ai-agent-security/pkg/keys"
)

func TestGenerateAndRoundTrip(t *testing.T) {
	kp, err := keys.GenerateECKeyPair()
	if err != nil {
		t.Fatalf("GenerateECKeyPair: %v", err)
	}

	jwk, err := keys.PublicKeyToJWK(kp.Public, "test-kid")
	if err != nil {
		t.Fatalf("PublicKeyToJWK: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" {
		t.Errorf("unexpected JWK fields: %+v", jwk)
	}
	if jwk.Kid != "test-kid" {
		t.Errorf("kid: want test-kid, got %s", jwk.Kid)
	}

	pub, err := keys.JWKToPublicKey(jwk)
	if err != nil {
		t.Fatalf("JWKToPublicKey: %v", err)
	}
	if pub.X.Cmp(kp.Public.X) != 0 || pub.Y.Cmp(kp.Public.Y) != 0 {
		t.Error("recovered public key does not match original")
	}
}

func TestJWKFromRawMessage(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	jwk, _ := keys.PublicKeyToJWK(kp.Public, "")
	raw, _ := json.Marshal(jwk)

	parsed, err := keys.JWKFromRawMessage(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("JWKFromRawMessage: %v", err)
	}
	if parsed.Alg != "ES256" {
		t.Errorf("alg: want ES256, got %s", parsed.Alg)
	}
}

func TestAlgIsAlwaysES256(t *testing.T) {
	kp, _ := keys.GenerateECKeyPair()
	jwk, _ := keys.PublicKeyToJWK(kp.Public, "")
	if jwk.Alg != "ES256" {
		t.Errorf("Alg: want ES256, got %q", jwk.Alg)
	}
}

func TestCoordinatePadding(t *testing.T) {
	// Run many times to hit the leading-zero padding case.
	for i := 0; i < 50; i++ {
		kp, _ := keys.GenerateECKeyPair()
		jwk, _ := keys.PublicKeyToJWK(kp.Public, "")
		pub, err := keys.JWKToPublicKey(jwk)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if pub.X.Cmp(kp.Public.X) != 0 || pub.Y.Cmp(kp.Public.Y) != 0 {
			t.Fatal("coordinate mismatch after padding round-trip")
		}
	}
}

func TestInvalidCurvePoint(t *testing.T) {
	jwk := &keys.JWK{
		Kty: "EC", Crv: "P-256", Alg: "ES256",
		X: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Y: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	_, err := keys.JWKToPublicKey(jwk)
	if err == nil {
		t.Error("expected error for invalid curve point")
	}
}
