package alaye

import (
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestGit_EffectiveMode_AutoDerives(t *testing.T) {
	cases := []struct {
		name string
		git  Git
		want string
	}{
		{"interval only", Git{Interval: expect.Duration(time.Minute)}, def.GitModePull},
		{"secret only", Git{Secret: "webhook-secret"}, def.GitModePush},
		{"both", Git{Interval: expect.Duration(time.Minute), Secret: "webhook-secret"}, def.GitModeBoth},
		{"neither", Git{}, def.GitModeAuto},
		{"explicit auto", Git{Mode: def.GitModeAuto, Interval: expect.Duration(time.Minute)}, def.GitModePull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.git.EffectiveMode(); got != tc.want {
				t.Fatalf("EffectiveMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGit_Validate_Modes(t *testing.T) {
	base := func(mode string) Git {
		return Git{
			Enabled:  expect.Active,
			ID:       "site",
			URL:      "https://example.com/site.git",
			Branch:   "main",
			Interval: expect.Duration(time.Minute),
			Secret:   "webhook-secret",
			Mode:     mode,
		}
	}
	set := func(g Git, interval time.Duration, secret, url string) Git {
		g.Interval = expect.Duration(interval)
		g.Secret = expect.Value(secret)
		g.URL = url
		return g
	}

	valid := []struct {
		name string
		git  Git
	}{
		{"auto pull", set(base(def.GitModeAuto), time.Minute, "", "https://example.com/site.git")},
		{"auto push", set(base(def.GitModeAuto), 0, "webhook-secret", "https://example.com/site.git")},
		{"auto both", set(base(def.GitModeAuto), time.Minute, "webhook-secret", "https://example.com/site.git")},
		{"pull", set(base(def.GitModePull), time.Minute, "", "https://example.com/site.git")},
		{"push", set(base(def.GitModePush), 0, "webhook-secret", "https://example.com/site.git")},
		{"push only", set(base(def.GitModePush), 0, "webhook-secret", "")},
		{"both", set(base(def.GitModeBoth), time.Minute, "webhook-secret", "https://example.com/site.git")},
	}
	for _, tc := range valid {
		t.Run("valid "+tc.name, func(t *testing.T) {
			if err := tc.git.Validate(); err != nil {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}

	invalid := []struct {
		name string
		git  Git
	}{
		{"pull missing interval", set(base(def.GitModePull), 0, "", "https://example.com/site.git")},
		{"pull missing url", set(base(def.GitModePull), time.Minute, "", "")},
		{"pull with secret", set(base(def.GitModePull), time.Minute, "webhook-secret", "https://example.com/site.git")},
		{"push missing secret", set(base(def.GitModePush), 0, "", "https://example.com/site.git")},
		{"push with interval", set(base(def.GitModePush), time.Minute, "webhook-secret", "https://example.com/site.git")},
		{"both missing url", set(base(def.GitModeBoth), time.Minute, "webhook-secret", "")},
		{"both missing interval", set(base(def.GitModeBoth), 0, "webhook-secret", "https://example.com/site.git")},
		{"both missing secret", set(base(def.GitModeBoth), time.Minute, "", "https://example.com/site.git")},
		{"unknown mode", set(base("sometimes"), time.Minute, "", "https://example.com/site.git")},
	}
	for _, tc := range invalid {
		t.Run("invalid "+tc.name, func(t *testing.T) {
			if err := tc.git.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid mode configuration")
			}
		})
	}
}

func TestGit_IsPullIsPush(t *testing.T) {
	cases := []struct {
		mode string
		pull bool
		push bool
	}{
		{def.GitModePull, true, false},
		{def.GitModePush, false, true},
		{def.GitModeBoth, true, true},
		{def.GitModeAuto, false, false},
	}
	for _, tc := range cases {
		g := Git{Mode: tc.mode}
		if got := g.IsPull(); got != tc.pull {
			t.Errorf("%s IsPull() = %v, want %v", tc.mode, got, tc.pull)
		}
		if got := g.IsPush(); got != tc.push {
			t.Errorf("%s IsPush() = %v, want %v", tc.mode, got, tc.push)
		}
	}
}
