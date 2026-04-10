package alaye

import (
	"html/template"
	"net"
	"regexp"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Security struct {
	Enabled        expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	TrustedProxies []string      `hcl:"trusted_proxies,attr" json:"trusted_proxies"`
	Firewall       Firewall      `hcl:"firewall,block" json:"firewall"`
	Keeper         Keeper        `hcl:"keeper,block" json:"keep"`
}

// Validate checks trusted proxy formats and delegates to Firewall.Validate.
func (s *Security) Validate() error {
	if s == nil {
		return nil
	}
	if s.Enabled.NotActive() {
		return nil
	}
	for i, proxy := range s.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("security: trusted_proxies[%d]=%q is invalid", i, proxy)
			}
		}
	}
	return s.Firewall.Validate()
}

type Defaults struct {
	Dynamic DefaultAction `hcl:"dynamic,block" json:"dynamic"`
	Static  DefaultAction `hcl:"static,block" json:"static"`
}

type DefaultAction struct {
	Action   string   `hcl:"action,attr" json:"action"`
	Duration Duration `hcl:"duration,attr" json:"duration"`
}

type Rule struct {
	Name        string   `hcl:"name,label" json:"name"`
	Description string   `hcl:"description,attr" json:"description"`
	Priority    int      `hcl:"priority,attr" json:"priority"`
	Type        string   `hcl:"type,attr" json:"type"`
	Action      string   `hcl:"action,attr" json:"action"`
	Duration    Duration `hcl:"duration,attr" json:"duration"`
	Match       Match    `hcl:"match,block" json:"match"`
}

// Validate checks that name is present and type is one of the accepted values.
func (r *Rule) Validate() error {
	if r == nil {
		return errors.New("nil rule")
	}
	if r.Name == "" {
		return errors.New("rule name required")
	}
	switch strings.ToLower(r.Type) {
	case "static", "dynamic", "whitelist":
	default:
		return errors.New("type must be 'static', 'dynamic', or 'whitelist'")
	}
	return r.Match.Validate()
}

type Match struct {
	Enabled   expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	IP        []string      `hcl:"ip,attr" json:"ip"`
	Path      []string      `hcl:"path,attr" json:"path"`
	Methods   []string      `hcl:"methods,attr" json:"methods"`
	Any       []Condition   `hcl:"any,block" json:"any"`
	All       []Condition   `hcl:"all,block" json:"all"`
	None      []Condition   `hcl:"none,block" json:"none"`
	Extract   *Extract      `hcl:"extract,block" json:"extract,omitempty"`
	Threshold *Threshold    `hcl:"threshold,block" json:"threshold,omitempty"`
}

// Validate checks all condition groups, extract, and threshold blocks.
func (m *Match) Validate() error {
	if m.Enabled.NotActive() {
		return nil
	}
	for i, c := range m.Any {
		if err := c.Validate(); err != nil {
			return errors.Newf("any[%d]: %w", i, err)
		}
	}
	for i, c := range m.All {
		if err := c.Validate(); err != nil {
			return errors.Newf("all[%d]: %w", i, err)
		}
	}
	for i, c := range m.None {
		if err := c.Validate(); err != nil {
			return errors.Newf("none[%d]: %w", i, err)
		}
	}
	if m.Extract != nil && m.Extract.Enabled.Active() {
		if err := m.Extract.Validate(); err != nil {
			return errors.Newf("extract: %w", err)
		}
	}
	if m.Threshold != nil && m.Threshold.Enabled.Active() {
		if err := m.Threshold.Validate(); err != nil {
			return errors.Newf("threshold: %w", err)
		}
	}
	return nil
}

type Condition struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Location   string        `hcl:"location,attr" json:"location"`
	Key        string        `hcl:"key,attr" json:"key"`
	Operator   string        `hcl:"operator,attr" json:"operator"`
	Value      string        `hcl:"value,attr" json:"value"`
	Pattern    string        `hcl:"pattern,attr" json:"pattern"`
	Negate     bool          `hcl:"negate,attr" json:"negate"`
	IgnoreCase bool          `hcl:"ignore_case,attr" json:"ignore_case"`

	Compiled *regexp.Regexp `hcl:"-" json:"-"`
}

// Validate checks location and compiles the pattern regex when present.
func (c *Condition) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	switch strings.ToLower(c.Location) {
	case "ip", "path", "method", "header", "headers", "query", "body", "uri", "bot", "":
	default:
		return errors.Newf("unknown location %q", c.Location)
	}
	if c.Pattern != "" {
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			return errors.Newf("invalid regex pattern %q: %w", c.Pattern, err)
		}
		c.Compiled = re
	}
	return nil
}

type Extract struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	From    string        `hcl:"from,attr" json:"from"`
	Pattern string        `hcl:"pattern,attr" json:"pattern"`
	As      string        `hcl:"as,attr" json:"as"`

	Regex *regexp.Regexp `hcl:"-" json:"-"`
}

// Validate checks that a pattern is present and compiles as a valid regex.
func (e *Extract) Validate() error {
	if e.Enabled.NotActive() {
		return nil
	}
	if e.Pattern == "" {
		return errors.New("extract pattern required")
	}
	re, err := regexp.Compile(e.Pattern)
	if err != nil {
		return errors.Newf("extract regex: %w", err)
	}
	e.Regex = re
	return nil
}

type Threshold struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Count    int           `hcl:"count,attr" json:"count"`
	Window   Duration      `hcl:"window,attr" json:"window"`
	TrackBy  string        `hcl:"track_by,attr" json:"track_by"`
	GroupBy  string        `hcl:"group_by,attr" json:"group_by"`
	OnExceed string        `hcl:"on_exceed,attr" json:"on_exceed"`
}

// Validate checks that count and window are positive when threshold is enabled.
func (t *Threshold) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	if t.Count <= 0 {
		return errors.New("threshold count must be > 0")
	}
	if t.Window <= 0 {
		return errors.New("threshold window must be > 0")
	}
	return nil
}

type Action struct {
	Name       string   `hcl:"name,label" json:"name"`
	Mitigation string   `hcl:"mitigation,attr" json:"mitigation"`
	Response   Response `hcl:"response,block" json:"response"`
	Logging    Logging  `hcl:"logging,block" json:"logging"`
}

type Response struct {
	Status       expect.Toggle     `hcl:"enabled,attr" json:"enabled"`
	ContentType  string            `hcl:"content_type,attr" json:"content_type"`
	BodyTemplate string            `hcl:"body_template,attr" json:"body_template"`
	Headers      map[string]string `hcl:"headers,attr" json:"headers"`
	StatusCode   int               `hcl:"status_code,attr" json:"status_code"`

	Template *template.Template `hcl:"-" json:"-"`
}

type Firewall struct {
	Status              expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Mode                string        `hcl:"mode,attr" json:"mode"`
	InspectBody         bool          `hcl:"inspect_body,attr" json:"inspect_body"`
	MaxInspectBytes     int64         `hcl:"max_inspect_bytes,attr" json:"max_inspect_bytes"`
	InspectContentTypes []string      `hcl:"inspect_content_types,attr" json:"inspect_content_types"`
	Defaults            Defaults      `hcl:"defaults,block" json:"defaults"`
	Rules               []Rule        `hcl:"rule,block" json:"rules"`
	Actions             []Action      `hcl:"action,block" json:"actions"`
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

type Keeper struct {
	// Enabled indicates whether the secret store is active.
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`

	// Logging specifies whether logging is enabled or disabled for the secret store.
	Logging expect.Toggle `hcl:"logging,attr" json:"logging"`

	// AutoLock is the duration after which the store auto-locks when idle (0 = disabled).
	AutoLock Duration `hcl:"auto_lock,attr" json:"auto_lock"`

	// Audit enables audit logging of all secret access (get/set/delete).
	Audit expect.Toggle `hcl:"audit,attr" json:"audit"`

	// Passphrase is the master passphrase to unlock the store.
	// This should be a secret reference (e.g., "env.SECRET_STORE_PASS") to avoid plaintext.
	Passphrase expect.Value `hcl:"passphrase,attr" json:"passphrase"` // can later be *security.Value
}
