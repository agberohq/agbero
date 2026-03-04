package alaye

import (
	"regexp"

	"github.com/olekukonko/errors"
)

type Rewrite struct {
	Pattern string         `hcl:"pattern" json:"pattern"`
	Target  string         `hcl:"target" json:"target"`
	Regex   *regexp.Regexp `hcl:"-" json:"-"`
}

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
