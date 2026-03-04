package alaye

import (
	"os"

	"github.com/olekukonko/errors"
)

type ErrorPages struct {
	// Maps status code "404" to file path "./errors/404.html"
	Pages map[string]string `hcl:"pages,optional" json:"pages"`
	// Fallback file for any unmapped 4xx/5xx error
	Default string `hcl:"default,optional" json:"default"`
}

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
