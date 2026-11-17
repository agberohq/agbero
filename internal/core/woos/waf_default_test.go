package woos

import (
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestDefaultGlobalResolvesRelativeWAFRulesDir(t *testing.T) {
	g := &alaye.Global{Security: alaye.Security{WAF: alaye.WAF{RulesDir: "rules"}}}
	D.Global(g, "/etc/agbero/agbero.hcl")
	want := filepath.Join("/etc/agbero", "rules")
	if g.Security.WAF.RulesDir != want {
		t.Fatalf("RulesDir = %q, want %q", g.Security.WAF.RulesDir, want)
	}
}
