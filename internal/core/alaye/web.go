package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Git struct {
	Enabled  Enabled       `hcl:"enabled,optional" json:"enabled"`
	URL      string        `hcl:"url" json:"url"`
	Branch   string        `hcl:"branch,optional" json:"branch"`
	Secret   Value         `hcl:"secret,optional" json:"secret"`     // Webhook HMAC secret
	Interval time.Duration `hcl:"interval,optional" json:"interval"` // Polling interval
}

func (g *Git) Validate() error {
	if g.Enabled.NotActive() {
		return nil
	}
	if g.URL == "" {
		return errors.New("git url is required when git is enabled")
	}
	return nil
}

type Web struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Root    WebRoot `hcl:"root,optional" json:"root"`
	Index   string  `hcl:"index,optional" json:"index"`
	Listing bool    `hcl:"listing,optional" json:"listing"`
	SPA     bool    `hcl:"spa,optional" json:"spa"`
	PHP     PHP     `hcl:"php,block" json:"php"`
	Git     Git     `hcl:"git,block" json:"git"`
}

func (w *Web) Validate() error {
	if w.Enabled.NotActive() {
		return nil
	}

	if err := w.Git.Validate(); err != nil {
		return errors.Newf("git: %w", err)
	}

	if w.Git.Enabled.NotActive() && !w.Root.IsSet() {
		return ErrRootRequired
	}

	if w.Index != "" && strings.Contains(w.Index, Slash) {
		return ErrIndexPath
	}

	if err := w.PHP.Validate(); err != nil {
		return errors.Newf("php: %w", err)
	}

	return nil
}

type WebRoot string

func (w WebRoot) IsSet() bool {
	return strings.TrimSpace(string(w)) != ""
}

// Display-only; do not use for presence.
func (w WebRoot) String() string {
	if !w.IsSet() {
		return "."
	}
	return string(w)
}
