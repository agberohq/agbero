package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

// WAF lives inside Security (global), mirroring the Firewall field.
type WAF struct {
	Status     expect.Toggle `hcl:"enabled,attr"    json:"enabled"`
	Driver     string        `hcl:"driver,attr"     json:"driver"`
	Mode       string        `hcl:"mode,attr"       json:"mode"`
	RulesDir   string        `hcl:"rules_dir,attr"  json:"rules_dir,omitempty"`
	Directives []string      `hcl:"directives,attr" json:"directives,omitempty"`
}

func (w *WAF) Validate() error {
	if w == nil || w.Status.Inactive() {
		return nil
	}
	if w.Driver != "coraza" {
		return errors.Newf("waf: unsupported driver %q — only \"coraza\" is supported", w.Driver)
	}
	switch w.Mode {
	case "active", "monitor":
	default:
		return errors.Newf("waf: mode must be \"active\" or \"monitor\", got %q", w.Mode)
	}
	if w.RulesDir == "" && len(w.Directives) == 0 {
		return errors.New("waf: at least one of rules_dir or directives must be set")
	}
	return nil
}

func (w WAF) IsZero() bool {
	return w.Status.IsZero() &&
		w.Driver == "" &&
		w.Mode == "" &&
		w.RulesDir == "" &&
		len(w.Directives) == 0
}

// WAFRoute is placed on Route, mirroring FirewallRoute.
type WAFRoute struct {
	Status       expect.Toggle `hcl:"enabled,attr"       json:"enabled"`
	IgnoreGlobal bool          `hcl:"ignore_global,attr" json:"ignore_global"`
	Mode         string        `hcl:"mode,attr"          json:"mode,omitempty"`
	Directives   []string      `hcl:"directives,attr"    json:"directives,omitempty"`
}

func (r WAFRoute) IsZero() bool {
	return r.Status.IsZero() &&
		!r.IgnoreGlobal &&
		r.Mode == "" &&
		len(r.Directives) == 0
}

// EffectiveMode resolves the mode: route overrides global when explicitly set.
func (r *WAFRoute) EffectiveMode(global *WAF) string {
	if r != nil && r.Mode != "" {
		return r.Mode
	}
	if global != nil {
		return global.Mode
	}
	return "monitor"
}
