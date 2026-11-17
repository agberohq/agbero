package woos

import (
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestDefaultGit_ModeDefaultsToAuto(t *testing.T) {
	g := alaye.Git{
		Enabled:  expect.Active,
		ID:       "site",
		URL:      "https://example.com/site.git",
		Interval: expect.Duration(time.Minute),
	}
	defaultGit(&g)
	if g.Mode != def.GitModeAuto {
		t.Fatalf("mode = %q, want %q", g.Mode, def.GitModeAuto)
	}
	if g.EffectiveMode() != def.GitModePull || !g.IsPull() || g.IsPush() {
		t.Fatalf("auto mode did not derive pull: effective=%q", g.EffectiveMode())
	}
}

func TestDefaultGit_PreservesExplicitMode(t *testing.T) {
	g := alaye.Git{
		Enabled: expect.Active,
		ID:      "site",
		URL:     "https://example.com/site.git",
		Secret:  "webhook-secret",
		Mode:    "PUSH",
	}
	defaultGit(&g)
	if g.Mode != def.GitModePush {
		t.Fatalf("mode = %q, want %q", g.Mode, def.GitModePush)
	}
}

func TestDefaultGit_DisabledDoesNotSetMode(t *testing.T) {
	g := alaye.Git{Enabled: expect.Inactive}
	defaultGit(&g)
	if g.Mode != "" {
		t.Fatalf("disabled git mode = %q, want empty", g.Mode)
	}
}
