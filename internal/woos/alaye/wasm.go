package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Wasm struct {
	Module      string            `hcl:"module"`                 // Path to .wasm file
	Config      map[string]string `hcl:"config,optional"`        // Key-values passed to WASM
	MaxBodySize int64             `hcl:"max_body_size,optional"` // Max bytes to copy to WASM (0 = none)
	Access      []string          `hcl:"access,optional"`        // "headers", "body", "method", "uri"
}

func (w *Wasm) Validate() error {
	if w.Module == "" {
		return errors.New("wasm: module path is required")
	}

	// Validate access list
	for _, a := range w.Access {
		switch strings.ToLower(a) {
		case "headers", "body", "method", "uri", "config":
			// ok
		default:
			return errors.Newf("wasm: unknown access capability %q", a)
		}
	}

	if w.MaxBodySize < 0 {
		return errors.New("wasm: max_body_size cannot be negative")
	}

	return nil
}

// Helper to check permissions quickly
func (w *Wasm) HasAccess(capability string) bool {
	for _, a := range w.Access {
		if strings.EqualFold(a, capability) {
			return true
		}
	}
	return false
}
