package alaye

import (
	"regexp"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Rule struct {
	Name        string          `hcl:"name,label" json:"name"`
	Description string          `hcl:"description,attr" json:"description"`
	Priority    int             `hcl:"priority,attr" json:"priority"`
	Type        string          `hcl:"type,attr" json:"type"`
	Action      string          `hcl:"action,attr" json:"action"`
	Duration    expect.Duration `hcl:"duration,attr" json:"duration"`
	Match       Match           `hcl:"match,block" json:"match"`
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
	Enabled  expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Count    int             `hcl:"count,attr" json:"count"`
	Window   expect.Duration `hcl:"window,attr" json:"window"`
	TrackBy  string          `hcl:"track_by,attr" json:"track_by"`
	GroupBy  string          `hcl:"group_by,attr" json:"group_by"`
	OnExceed string          `hcl:"on_exceed,attr" json:"on_exceed"`
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
