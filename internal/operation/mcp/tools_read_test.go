package mcp

import (
	"context"
	"testing"
	"time"
)

func TestStatusToolRequiresReadScope(t *testing.T) {
	d := ReadDeps{
		Version:        "v1.2.3",
		StartedAt:      time.Now().Add(-time.Minute),
		KeeperLocked:   func() bool { return false },
		ClusterMembers: func() int { return 3 },
		AdminEnabled:   true,
	}

	ctx := WithClaims(context.Background(), &Claims{Scope: ScopeRead})
	if _, out, err := d.status(ctx, nil, struct{}{}); err != nil {
		t.Fatalf("status: %v", err)
	} else if out.Version != "v1.2.3" || out.ClusterMembers != 3 || !out.AdminEnabled {
		t.Fatalf("status output = %+v", out)
	}

	if _, _, err := d.status(context.Background(), nil, struct{}{}); err == nil {
		t.Fatal("status allowed a request without claims")
	}
}

func TestSystemToolRequiresReadScope(t *testing.T) {
	d := ReadDeps{Version: "v1", Commit: "abc", BuildDate: "today"}
	ctx := WithClaims(context.Background(), &Claims{Scope: ScopeRead})
	if _, out, err := d.system(ctx, nil, struct{}{}); err != nil {
		t.Fatalf("system: %v", err)
	} else if out.Version != "v1" || out.OS == "" {
		t.Fatalf("system output = %+v", out)
	}
}
