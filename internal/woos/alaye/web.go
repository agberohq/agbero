package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Web struct {
	Root  WebRoot `hcl:"root,optional"`
	Index string  `hcl:"index,optional"`
}

func (w *Web) Validate() error {
	// Semantic check: root must be explicitly set for a web route
	if !w.Root.IsSet() {
		return errors.New("root is required for web block")
	}

	if w.Index != "" && strings.Contains(w.Index, "/") {
		return errors.New("index cannot contain path separators")
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
