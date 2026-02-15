package alaye

import (
	"html/template"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) TimeDuration() time.Duration {
	return time.Duration(d)
}

type Security struct {
	Enabled        bool      `hcl:"enabled" json:"enabled"`
	TrustedProxies []string  `hcl:"trusted_proxies,optional" json:"trusted_proxies"`
	Firewall       *Firewall `hcl:"firewall,block" json:"firewall,omitempty"`
}

type Firewall struct {
	Enabled             bool      `hcl:"enabled" json:"enabled"`
	Mode                string    `hcl:"mode,optional" json:"mode"`
	InspectBody         bool      `hcl:"inspect_body,optional" json:"inspect_body"`
	MaxInspectBytes     int64     `hcl:"max_inspect_bytes,optional" json:"max_inspect_bytes"`
	InspectContentTypes []string  `hcl:"inspect_content_types,optional" json:"inspect_content_types"`
	Defaults            *Defaults `hcl:"defaults,block" json:"defaults"`
	Rules               []*Rule   `hcl:"rule,block" json:"rules"`
	Actions             []*Action `hcl:"action,block" json:"actions"`
}

type Defaults struct {
	Dynamic *DefaultAction `hcl:"dynamic,block" json:"dynamic"`
	Static  *DefaultAction `hcl:"static,block" json:"static"`
}

type DefaultAction struct {
	Action   string   `hcl:"action,optional" json:"action"`
	Duration Duration `hcl:"duration,optional" json:"duration"`
}

type Rule struct {
	Name        string   `hcl:"name,label" json:"name"`
	Description string   `hcl:"description,optional" json:"description"`
	Priority    int      `hcl:"priority,optional" json:"priority"`
	Type        string   `hcl:"type" json:"type"`
	Action      string   `hcl:"action,optional" json:"action"`
	Duration    Duration `hcl:"duration,optional" json:"duration"`
	Match       *Match   `hcl:"match,block" json:"match"`
}

type Match struct {
	IP        []string     `hcl:"ip,optional" json:"ip"`
	Path      []string     `hcl:"path,optional" json:"path"`
	Methods   []string     `hcl:"methods,optional" json:"methods"`
	Any       []*Condition `hcl:"any,block" json:"any"`
	All       []*Condition `hcl:"all,block" json:"all"`
	None      []*Condition `hcl:"none,block" json:"none"`
	Extract   *Extract     `hcl:"extract,block" json:"extract"`
	Threshold *Threshold   `hcl:"threshold,block" json:"threshold"`
}

type Condition struct {
	Location   string `hcl:"location" json:"location"`
	Key        string `hcl:"key,optional" json:"key"`
	Operator   string `hcl:"operator,optional" json:"operator"`
	Value      string `hcl:"value,optional" json:"value"`
	Pattern    string `hcl:"pattern,optional" json:"pattern"`
	Negate     bool   `hcl:"negate,optional" json:"negate"`
	IgnoreCase bool   `hcl:"ignore_case,optional" json:"ignore_case"`

	Compiled *regexp.Regexp `hcl:"-" json:"-"`
}

type Extract struct {
	From    string         `hcl:"from" json:"from"`
	Pattern string         `hcl:"pattern" json:"pattern"`
	As      string         `hcl:"as" json:"as"`
	Regex   *regexp.Regexp `hcl:"-" json:"-"`
}

type Threshold struct {
	Count    int      `hcl:"count" json:"count"`
	Window   Duration `hcl:"window" json:"window"`
	TrackBy  string   `hcl:"track_by" json:"track_by"`
	GroupBy  string   `hcl:"group_by,optional" json:"group_by"`
	OnExceed string   `hcl:"on_exceed" json:"on_exceed"`
}

type Action struct {
	Name           string    `hcl:"name,label" json:"name"`
	FirewallAction string    `hcl:"firewall_action" json:"firewall_action"`
	Response       *Response `hcl:"response,block" json:"response"`
	Logging        *Logging  `hcl:"logging,block" json:"logging"`
}

type Response struct {
	StatusCode   int               `hcl:"status_code" json:"status_code"`
	ContentType  string            `hcl:"content_type,optional" json:"content_type"`
	BodyTemplate string            `hcl:"body_template,optional" json:"body_template"`
	Headers      map[string]string `hcl:"headers,optional" json:"headers"`

	Template *template.Template `hcl:"-" json:"-"`
}

func (s *Security) Validate() error {
	for i, proxy := range s.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("security: trusted_proxies[%d]=%q is invalid", i, proxy)
			}
		}
	}

	if s.Firewall != nil {
		return s.Firewall.Validate()
	}
	return nil
}

func (f *Firewall) Validate() error {
	if !f.Enabled {
		return nil
	}

	f.Mode = strings.ToLower(f.Mode)
	if f.Mode == "" {
		f.Mode = "active"
	}
	if f.Mode != "active" && f.Mode != "verbose" && f.Mode != "monitor" {
		return errors.New("firewall: mode must be 'active' or 'verbose'")
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

	for _, a := range f.Actions {
		if a.Name == "" {
			return errors.New("firewall: action name required")
		}
		if a.Response != nil && a.Response.BodyTemplate != "" {
			t, err := template.New("resp-" + a.Name).Parse(a.Response.BodyTemplate)
			if err != nil {
				return errors.Newf("action %q template error: %w", a.Name, err)
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

func (r *Rule) Validate() error {
	r.Type = strings.ToLower(r.Type)
	switch r.Type {
	case "static", "dynamic", "whitelist":
	default:
		return errors.New("type must be 'static', 'dynamic', or 'whitelist'")
	}

	if r.Match != nil {
		if err := r.Match.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Match) Validate() error {
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

	if m.Extract != nil {
		if m.Extract.Pattern == "" {
			return errors.New("extract pattern required")
		}
		re, err := regexp.Compile(m.Extract.Pattern)
		if err != nil {
			return errors.Newf("extract regex: %w", err)
		}
		m.Extract.Regex = re
	}

	if m.Threshold != nil {
		if m.Threshold.Count <= 0 {
			return errors.New("threshold count must be > 0")
		}
		if m.Threshold.Window.TimeDuration() <= 0 {
			return errors.New("threshold window must be > 0")
		}
	}

	return nil
}

func (c *Condition) Validate() error {
	c.Location = strings.ToLower(c.Location)
	switch c.Location {
	case "ip", "path", "method", "header", "headers", "query", "body", "uri":
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
