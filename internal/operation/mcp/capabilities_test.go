package mcp

import (
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestRegistryMatchesConfigCapabilities(t *testing.T) {
	for _, name := range alaye.MCPReadCapabilities {
		if _, ok := Lookup(ClassRead, name); !ok {
			t.Errorf("read capability %q is in alaye but not the registry", name)
		}
	}
	for _, name := range alaye.MCPPlanCapabilities {
		if _, ok := Lookup(ClassPlan, name); !ok {
			t.Errorf("plan capability %q is in alaye but not the registry", name)
		}
	}
}

func TestRegistryHasNoApplyClassOrEmptyTools(t *testing.T) {
	for _, c := range Registry {
		if c.Class != ClassRead && c.Class != ClassPlan {
			t.Errorf("%q has class %q; only read/plan exist", c.Name, c.Class)
		}
		if c.Tool == "" {
			t.Errorf("%q has no tool", c.Name)
		}
	}
}

func TestPlanOnlyCapabilityIsNotReadable(t *testing.T) {
	if _, ok := Lookup(ClassRead, "config.plan"); ok {
		t.Fatal("config.plan must not be a read capability")
	}
	if _, ok := Lookup(ClassPlan, "config.plan"); !ok {
		t.Fatal("config.plan must be a plan capability")
	}
}

func TestRegistryEntriesAreUnique(t *testing.T) {
	seen := make(map[string]struct{}, len(Registry))
	for _, c := range Registry {
		key := string(c.Class) + ":" + c.Name
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate registry entry %s", key)
		}
		seen[key] = struct{}{}
	}
}
