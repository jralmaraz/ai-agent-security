package federation_test

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/jralmaraz/wimse-agent-fabric/pkg/federation"
	"github.com/jralmaraz/wimse-agent-fabric/pkg/keys"
)

const (
	anchorID  = "https://trust-anchor.corporate.example"
	idpAID    = "https://idp.agent-fabric-a.example"
	idpBID    = "https://idp.agent-fabric-b.example"
	idpAOrg   = "Acme Corp Agent Fabric A"
)

type env struct {
	anchorKP *keys.ECKeyPair
	idpAKP   *keys.ECKeyPair
	idpBKP   *keys.ECKeyPair
}

func setupEnv(t *testing.T) *env {
	t.Helper()
	anchorKP, _ := keys.GenerateECKeyPair()
	idpAKP, _ := keys.GenerateECKeyPair()
	idpBKP, _ := keys.GenerateECKeyPair()
	return &env{anchorKP: anchorKP, idpAKP: idpAKP, idpBKP: idpBKP}
}

func buildAnchors(e *env) map[string]*ecdsa.PublicKey {
	return map[string]*ecdsa.PublicKey{anchorID: e.anchorKP.Public}
}

func TestBuildAndParseEntityConfiguration(t *testing.T) {
	e := setupEnv(t)
	ecJWT, err := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildEntityConfiguration: %v", err)
	}
	ec, err := federation.ParseEntityConfiguration(ecJWT)
	if err != nil {
		t.Fatalf("ParseEntityConfiguration: %v", err)
	}
	if ec.Issuer != idpAID {
		t.Errorf("iss: want %q got %q", idpAID, ec.Issuer)
	}
	if len(ec.JWKS.Keys) != 1 {
		t.Errorf("JWKS.Keys: want 1 got %d", len(ec.JWKS.Keys))
	}
	if len(ec.AuthorityHints) != 1 || ec.AuthorityHints[0] != anchorID {
		t.Errorf("authority_hints: %v", ec.AuthorityHints)
	}
}

func TestVerifyEntityConfiguration_CorrectKey(t *testing.T) {
	e := setupEnv(t)
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	ec, err := federation.VerifyEntityConfiguration(ecJWT, e.idpAKP.Public)
	if err != nil {
		t.Fatalf("VerifyEntityConfiguration: %v", err)
	}
	if ec.Issuer != idpAID {
		t.Errorf("iss: want %q got %q", idpAID, ec.Issuer)
	}
}

func TestVerifyEntityConfiguration_WrongKey(t *testing.T) {
	e := setupEnv(t)
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	_, err := federation.VerifyEntityConfiguration(ecJWT, e.idpBKP.Public)
	if err == nil {
		t.Error("expected error when verifying EC with wrong key")
	}
}

func TestBuildAndVerifySubordinateStatement(t *testing.T) {
	e := setupEnv(t)
	ssJWT, err := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	if err != nil {
		t.Fatalf("BuildSubordinateStatement: %v", err)
	}
	ss, err := federation.VerifySubordinateStatement(ssJWT, e.anchorKP.Public)
	if err != nil {
		t.Fatalf("VerifySubordinateStatement: %v", err)
	}
	if ss.Subject != idpAID {
		t.Errorf("sub: want %q got %q", idpAID, ss.Subject)
	}
}

func TestInMemoryResolver_HappyPath(t *testing.T) {
	e := setupEnv(t)
	resolver := makeResolver(t, e)

	entity, err := resolver.Resolve(context.Background(), idpAID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	pub, err := entity.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !pub.Equal(e.idpAKP.Public) {
		t.Error("resolved key does not match IdP-A's public key")
	}
}

func TestInMemoryResolver_UnknownEntity(t *testing.T) {
	e := setupEnv(t)
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	_, err := resolver.Resolve(context.Background(), "https://rogue.example")
	if err == nil {
		t.Error("expected error for unknown entity")
	}
}

func TestInMemoryResolver_TamperedEC(t *testing.T) {
	e := setupEnv(t)
	tamperedEC, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpBKP.Private, "wrong-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	ssJWT, _ := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	resolver.RegisterEntityConfig(idpAID, tamperedEC)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)

	_, err := resolver.Resolve(context.Background(), idpAID)
	if err == nil {
		t.Error("expected error: EC key does not match what SS certified")
	}
}

func TestInMemoryResolver_UntrustedAnchor(t *testing.T) {
	e := setupEnv(t)
	rogueKP, _ := keys.GenerateECKeyPair()
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{"https://rogue-anchor.example"}, time.Hour,
	)
	ssJWT, _ := federation.BuildSubordinateStatement(
		"https://rogue-anchor.example", idpAID,
		e.idpAKP.Public, "idpa-key",
		rogueKP.Private, "rogue-key",
		time.Hour,
	)
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	resolver.RegisterEntityConfig(idpAID, ecJWT)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)

	_, err := resolver.Resolve(context.Background(), idpAID)
	if err == nil {
		t.Error("expected error: rogue anchor not trusted")
	}
}

func makeResolver(t *testing.T, e *env) *federation.InMemoryResolver {
	t.Helper()
	resolver := federation.NewInMemoryResolver(buildAnchors(e))
	ecJWT, _ := federation.BuildEntityConfiguration(
		idpAID, e.idpAKP.Private, "idpa-key", idpAOrg,
		[]string{anchorID}, time.Hour,
	)
	ssJWT, _ := federation.BuildSubordinateStatement(
		anchorID, idpAID,
		e.idpAKP.Public, "idpa-key",
		e.anchorKP.Private, "anchor-key",
		time.Hour,
	)
	resolver.RegisterEntityConfig(idpAID, ecJWT)
	resolver.RegisterSubordinateStatement(idpAID, ssJWT)
	return resolver
}
