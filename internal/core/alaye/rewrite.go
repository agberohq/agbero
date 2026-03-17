package alaye

import (
	"regexp"

	"github.com/olekukonko/errors"
)

type Rewrite struct {
	Pattern string         `hcl:"pattern,attr" json:"pattern"`
	Target  string         `hcl:"target,attr" json:"target"`
	Regex   *regexp.Regexp `hcl:"-" json:"-"`
}

// Validate checks that pattern and target are present and that pattern compiles as a valid regex.
func (r *Rewrite) Validate() error {
	if r.Pattern == "" {
		return errors.New("rewrite: pattern is required")
	}
	if r.Target == "" {
		return errors.New("rewrite: target is required")
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return errors.Newf("rewrite: invalid regex %q: %w", r.Pattern, err)
	}
	r.Regex = re
	return nil
}
