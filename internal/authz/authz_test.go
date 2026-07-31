package authz_test

import (
	"context"
	"testing"

	"github.com/jralmaraz/wimse-agent-fabric/internal/authz"
)

const (
	agentA = "spiffe://cloud-a.example/agent/orchestrator"
	agentB = "spiffe://cloud-a.example/agent/executor"
	tool   = "tool:weather-api"
	db     = "tool:internal-db"
)

func newAuthz(t *testing.T) *authz.InMemoryAuthorizer {
	t.Helper()
	a := authz.NewInMemoryAuthorizer()
	a.Allow(agentA, tool, authz.ActionCall)
	a.Allow(agentA, db, authz.ActionWrite)
	a.Allow("*", "tool:public-api", authz.ActionRead)
	return a
}

func TestInMemory_HappyPath(t *testing.T) {
	a := newAuthz(t)
	d, err := a.Authorize(context.Background(), authz.Request{
		Subject: agentA,
		Object:  tool,
		Action:  authz.ActionCall,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected allowed, got: %s", d.Reason)
	}
}

func TestInMemory_Denied(t *testing.T) {
	a := newAuthz(t)
	d, err := a.Authorize(context.Background(), authz.Request{
		Subject: agentB,
		Object:  tool,
		Action:  authz.ActionCall,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected denied, got: %s", d.Reason)
	}
}

func TestInMemory_ActionInheritance_CanCallImpliesCanRead(t *testing.T) {
	a := newAuthz(t)
	// agentA has can_call on tool; can_read should also be allowed.
	d, err := a.Authorize(context.Background(), authz.Request{
		Subject: agentA,
		Object:  tool,
		Action:  authz.ActionRead,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allowed {
		t.Errorf("can_call should imply can_read; got: %s", d.Reason)
	}
}

func TestInMemory_ActionInheritance_CanWriteImpliesCanRead(t *testing.T) {
	a := newAuthz(t)
	// agentA has can_write on db; can_read should also be allowed.
	d, err := a.Authorize(context.Background(), authz.Request{
		Subject: agentA,
		Object:  db,
		Action:  authz.ActionRead,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !d.Allowed {
		t.Errorf("can_write should imply can_read; got: %s", d.Reason)
	}
}

func TestInMemory_WildcardSubject(t *testing.T) {
	a := newAuthz(t)
	// any agent may read tool:public-api
	for _, sub := range []string{agentA, agentB, "spiffe://other.example/x"} {
		d, err := a.Authorize(context.Background(), authz.Request{
			Subject: sub,
			Object:  "tool:public-api",
			Action:  authz.ActionRead,
		})
		if err != nil {
			t.Fatalf("Authorize(%s): %v", sub, err)
		}
		if !d.Allowed {
			t.Errorf("wildcard should allow %s; got: %s", sub, d.Reason)
		}
	}
}

func TestInMemory_MissingSubjectOrObject(t *testing.T) {
	a := authz.NewInMemoryAuthorizer()
	if _, err := a.Authorize(context.Background(), authz.Request{Object: tool, Action: authz.ActionRead}); err == nil {
		t.Error("expected error for missing subject")
	}
	if _, err := a.Authorize(context.Background(), authz.Request{Subject: agentA, Action: authz.ActionRead}); err == nil {
		t.Error("expected error for missing object")
	}
}

func TestInMemory_CallDoesNotImplyWrite(t *testing.T) {
	a := authz.NewInMemoryAuthorizer()
	a.Allow(agentA, tool, authz.ActionCall)
	d, err := a.Authorize(context.Background(), authz.Request{
		Subject: agentA,
		Object:  tool,
		Action:  authz.ActionWrite,
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if d.Allowed {
		t.Error("can_call should NOT imply can_write")
	}
}
