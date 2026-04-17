package alaye

import (
	"html/template"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Firewall struct {
	Status              expect.Toggle    `hcl:"enabled,attr" json:"enabled"`
	Mode                string           `hcl:"mode,attr" json:"mode"`
	InspectBody         bool             `hcl:"inspect_body,attr" json:"inspect_body"`
	MaxInspectBytes     int64            `hcl:"max_inspect_bytes,attr" json:"max_inspect_bytes"`
	InspectContentTypes []string         `hcl:"inspect_content_types,attr" json:"inspect_content_types"`
	Defaults            FirewallDefaults `hcl:"defaults,block" json:"defaults"`
	Actions             []FirewallAction `hcl:"action,block" json:"actions"`
	Rules               []Rule           `hcl:"rule,block" json:"rules"`
}

// Validate checks firewall mode and delegates rule and action validation.
// It does not set defaults — all defaults are applied by woos.defaultFirewall.
func (f *Firewall) Validate() error {
	if f.Status.Inactive() {
		return nil
	}
	switch f.Mode {
	case "active", "verbose", "monitor":
	default:
		return errors.New("firewall: mode must be 'active', 'verbose', or 'monitor'")
	}
	for i, a := range f.Actions {
		if a.Name == "" {
			return errors.New("firewall: action name required")
		}
		if a.Response.BodyTemplate != "" {
			t, err := template.New("resp-" + a.Name).Parse(a.Response.BodyTemplate)
			if err != nil {
				return errors.Newf("action[%d] %q template error: %w", i, a.Name, err)
			}
			a.Response.Template = t
		}
	}
	for i, r := range f.Rules {
		if err := r.Validate(); err != nil {
			return errors.Newf("rule[%d]: %w", i, err)
		}
	}
	return nil
}

type FirewallRoute struct {
	Status       expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	IgnoreGlobal bool          `hcl:"ignore_global,attr" json:"ignore_global"`
	ApplyRules   []string      `hcl:"apply_rules,attr" json:"apply_rules"`
	Rules        []Rule        `hcl:"rule,block" json:"rules,omitempty"`
}

func (f FirewallRoute) IsZero() bool {
	return f.Status.IsZero() &&
		!f.IgnoreGlobal &&
		len(f.ApplyRules) == 0 &&
		len(f.Rules) == 0
}

type FirewallDefaults struct {
	Dynamic FirewallDefaultAction `hcl:"dynamic,block" json:"dynamic"`
	Static  FirewallDefaultAction `hcl:"static,block" json:"static"`
}

type FirewallDefaultAction struct {
	Action   string          `hcl:"action,attr" json:"action"`
	Duration expect.Duration `hcl:"duration,attr" json:"duration"`
}

type FirewallAction struct {
	Name       string   `hcl:"name,label" json:"name"`
	Mitigation string   `hcl:"mitigation,attr" json:"mitigation"`
	Response   Response `hcl:"response,block" json:"response"`
	Logging    Logging  `hcl:"logging,block" json:"logging"`
}
