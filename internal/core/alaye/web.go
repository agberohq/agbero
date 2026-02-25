package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Root    WebRoot `hcl:"root,optional" json:"root"`
	Index   string  `hcl:"index,optional" json:"index"`
	Listing bool    `hcl:"listing,optional" json:"listing"`
	PHP     PHP     `hcl:"php,block" json:"php"`
}

func (w *Web) Validate() error {

	if w.Enabled.NotActive() {
		return nil
	}

	if !w.Root.IsSet() {
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
