package alaye

import (
	"os"

	"github.com/olekukonko/errors"
)

type ErrorPages struct {
	Pages   map[string]string `hcl:"pages,attr" json:"pages"`
	Default string            `hcl:"default,attr" json:"default"`
}

// Validate checks that every configured error page file exists on disk.
func (e *ErrorPages) Validate() error {
	for code, path := range e.Pages {
		if _, err := os.Stat(path); err != nil {
			return errors.Newf("error_pages: code %s file %q not found: %w", code, path, err)
		}
	}
	if e.Default != "" {
		if _, err := os.Stat(e.Default); err != nil {
			return errors.Newf("error_pages: default file %q not found: %w", e.Default, err)
		}
	}
	return nil
}
