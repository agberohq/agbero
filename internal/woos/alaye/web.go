package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Web struct {
	Root  WebRoot `hcl:"root"`
	Index string  `hcl:"index,optional"`
}

type WebRoot string

func (w WebRoot) String() string {
	if w == "" {
		return "."
	}
	return string(w)
}

func (w *Web) Validate() error {
	// Root validation
	if w.Root.String() == "" {
		return errors.New("root is required for web block")
	}
	// Root must be an absolute path
	if !strings.HasPrefix(w.Root.String(), "/") {
		return errors.New("root must be an absolute path")
	}

	// Index validation (if provided)
	if w.Index != "" {
		if strings.Contains(w.Index, "/") {
			return errors.New("index cannot contain path separators")
		}
	}

	return nil
}
