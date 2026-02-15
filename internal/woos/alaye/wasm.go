package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Wasm struct {
	Enabled     Enabled           `hcl:"enabled,optional" json:"enabled"`
	Module      string            `hcl:"module" json:"module"`                        // Path to .wasm file
	Config      map[string]string `hcl:"config,optional" json:"config"`               // Key-values passed to WASM
	MaxBodySize int64             `hcl:"max_body_size,optional" json:"max_body_size"` // Max bytes to copy to WASM (0 = none)
	Access      []string          `hcl:"access,optional" json:"access"`               // "headers", "body", "method", "uri"
}

func (w *Wasm) Validate() error {
	if w.Enabled.No() {
		return nil
	}

	if w.Module == "" {
		return ErrModulePathRequired
	}

	// Validate access list
	for _, a := range w.Access {
		switch strings.ToLower(a) {
		case AccessHeaders, AccessBody, AccessMethod, AccessURI, AccessConfig:
			// ok
		default:
			return errors.Newf("%w %q", ErrUnknownCapability, a)
		}
	}

	if w.MaxBodySize < 0 {
		return ErrNegativeBodySize
	}

	return nil
}

// HasAccess is a helper to check permissions quickly
func (w *Wasm) HasAccess(capability string) bool {
	for _, a := range w.Access {
		if strings.EqualFold(a, capability) {
			return true
		}
	}
	return false
}
