package mcp

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func testHost() *alaye.Host {
	return &alaye.Host{
		Domains: []string{"app.example.com"},
		Routes: []alaye.Route{{
			Path:    "/api",
			Enabled: expect.Active,
			Backends: alaye.Backend{
				Enabled: expect.Active,
				Servers: []alaye.Server{alaye.NewServer("http://127.0.0.1:9000")},
			},
		}},
	}
}

func TestApplyPlanPatchRouteField(t *testing.T) {
	out, changes, risk, err := applyPlanPatch(testHost(), []PatchOp{{
		Op: "replace", Path: "route[/api].enabled", Value: "off",
	}})
	if err != nil {
		t.Fatalf("applyPlanPatch: %v", err)
	}
	if len(out.Routes) != 1 || out.Routes[0].Enabled.Active() {
		t.Fatalf("route not patched: %+v", out.Routes)
	}
	if len(changes) != 1 || risk != "medium" {
		t.Fatalf("changes=%v risk=%q", changes, risk)
	}
}

func TestApplyPlanPatchRejectsRedTier(t *testing.T) {
	if _, _, _, err := applyPlanPatch(testHost(), []PatchOp{{
		Op: "replace", Path: "admin.address", Value: "0.0.0.0:9090",
	}}); err == nil {
		t.Fatal("red-tier admin.address was accepted")
	}
}

func TestPlanTier(t *testing.T) {
	if planTier("route.compression.enabled") != "green" {
		t.Fatal("compression should be green")
	}
	if planTier("route.backends") != "amber" {
		t.Fatal("backends should be amber")
	}
	if planTier("keeper.passphrase") != "red" {
		t.Fatal("keeper should be red")
	}
	if planTier("route[/api].backends.servers") != "amber" {
		t.Fatal("route backends should be amber")
	}
	if planTier("route[/api].compression.enabled") != "green" {
		t.Fatal("route compression should be green")
	}
}
