package alaye

import (
	"html/template"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Security struct {
	Enabled        Enabled  `hcl:"enabled,optional" json:"enabled"`
	TrustedProxies []string `hcl:"trusted_proxies,optional" json:"trusted_proxies"`
	Firewall       Firewall `hcl:"firewall,block" json:"firewall,omitempty"`
}

type Defaults struct {
	Dynamic DefaultAction `hcl:"dynamic,block" json:"dynamic"`
	Static  DefaultAction `hcl:"static,block" json:"static"`
}

type DefaultAction struct {
	Action   string        `hcl:"action,optional" json:"action"`
	Duration time.Duration `hcl:"duration,optional" json:"duration"`
}

type Rule struct {
	Name        string        `hcl:"name,label" json:"name"`
	Description string        `hcl:"description,optional" json:"description"`
	Priority    int           `hcl:"priority,optional" json:"priority"`
	Type        string        `hcl:"type,optional" json:"type"`
	Action      string        `hcl:"action,optional" json:"action"`
	Duration    time.Duration `hcl:"duration,optional" json:"duration"`
	Match       Match         `hcl:"match,block" json:"match"`
}

func (r *Rule) Validate() error {
	if r == nil {
		return errors.New("nil rule")
	}

	if r.Name == "" {
		return errors.New("rule name required")
	}

	r.Type = strings.ToLower(r.Type)
	switch r.Type {
	case "static", "dynamic", "whitelist":
	default:
		return errors.New("type must be 'static', 'dynamic', or 'whitelist'")
	}

	if err := r.Match.Validate(); err != nil {
		return err
	}

	return nil
}

type Match struct {
	Enabled   Enabled     `hcl:"enabled,optional" json:"enabled"`
	IP        []string    `hcl:"ip,optional" json:"ip"`
	Path      []string    `hcl:"path,optional" json:"path"`
	Methods   []string    `hcl:"methods,optional" json:"methods"`
	Any       []Condition `hcl:"any,block" json:"any"`
	All       []Condition `hcl:"all,block" json:"all"`
	None      []Condition `hcl:"none,block" json:"none"`
	Extract   *Extract    `hcl:"extract,block" json:"extract,omitempty"`
	Threshold *Threshold  `hcl:"threshold,block" json:"threshold,omitempty"`
}

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
	Enabled    Enabled `hcl:"enabled,optional" json:"enabled"`
	Location   string  `hcl:"location,optional" json:"location"`
	Key        string  `hcl:"key,optional" json:"key"`
	Operator   string  `hcl:"operator,optional" json:"operator"`
	Value      string  `hcl:"value,optional" json:"value"`
	Pattern    string  `hcl:"pattern,optional" json:"pattern"`
	Negate     bool    `hcl:"negate,optional" json:"negate"`
	IgnoreCase bool    `hcl:"ignore_case,optional" json:"ignore_case"`

	Compiled *regexp.Regexp `hcl:"-" json:"-"`
}

func (c *Condition) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	c.Location = strings.ToLower(c.Location)
	switch c.Location {
	case "ip", "path", "method", "header", "headers", "query", "body", "uri", "":
		// Empty location is allowed (defaults will be handled elsewhere)
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
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	From    string  `hcl:"from,optional" json:"from"`
	Pattern string  `hcl:"pattern,optional" json:"pattern"`
	As      string  `hcl:"as,optional" json:"as"`

	Regex *regexp.Regexp `hcl:"-" json:"-"`
}

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
	Enabled  Enabled       `hcl:"enabled,optional" json:"enabled"`
	Count    int           `hcl:"count,optional" json:"count"`
	Window   time.Duration `hcl:"window,optional" json:"window"`
	TrackBy  string        `hcl:"track_by,optional" json:"track_by"`
	GroupBy  string        `hcl:"group_by,optional" json:"group_by"`
	OnExceed string        `hcl:"on_exceed,optional" json:"on_exceed"`
}

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
	Response   Response `hcl:"response,block" json:"response"`
	Logging    Logging  `hcl:"logging,block" json:"logging"`
	Mitigation string   `hcl:"mitigation,optional" json:"mitigation"`
}

type Response struct {
	Status       Enabled            `hcl:"enabled,optional" json:"enabled"`
	ContentType  string             `hcl:"content_type,optional" json:"content_type"`
	BodyTemplate string             `hcl:"body_template,optional" json:"body_template"`
	Headers      map[string]string  `hcl:"headers,optional" json:"headers"`
	StatusCode   int                `hcl:"status_code,optional" json:"status_code"`
	Template     *template.Template `hcl:"-" json:"-"`
}

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

type Firewall struct {
	Status              Enabled  `hcl:"enabled,optional" json:"enabled"`
	Mode                string   `hcl:"mode,optional" json:"mode"`
	InspectBody         bool     `hcl:"inspect_body,optional" json:"inspect_body"`
	MaxInspectBytes     int64    `hcl:"max_inspect_bytes,optional" json:"max_inspect_bytes"`
	InspectContentTypes []string `hcl:"inspect_content_types,optional" json:"inspect_content_types"`
	Defaults            Defaults `hcl:"defaults,block" json:"defaults"`
	Rules               []Rule   `hcl:"rule,block" json:"rules"`
	Actions             []Action `hcl:"action,block" json:"actions"`
}

func (f *Firewall) Validate() error {
	if f.Status.Inactive() {
		return nil
	}

	f.Mode = strings.ToLower(f.Mode)
	if f.Mode == "" {
		f.Mode = "active"
	}
	if f.Mode != "active" && f.Mode != "verbose" && f.Mode != "monitor" {
		return errors.New("firewall: mode must be 'active', 'verbose', or 'monitor'")
	}

	if f.MaxInspectBytes == 0 {
		f.MaxInspectBytes = 8192
	}
	if len(f.InspectContentTypes) == 0 {
		f.InspectContentTypes = []string{
			"application/json",
			"application/xml",
			"application/x-www-form-urlencoded",
			"text/plain",
		}
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
	Status       Enabled  `hcl:"enabled,optional" json:"enabled"`
	IgnoreGlobal bool     `hcl:"ignore_global,optional" json:"ignore_global"`
	ApplyRules   []string `hcl:"apply_rules,optional" json:"apply_rules"`
	Rules        []Rule   `hcl:"rule,block" json:"rules,omitempty"`
}
