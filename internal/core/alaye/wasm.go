package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Wasm struct {
	Enabled     Enabled           `hcl:"enabled,attr" json:"enabled"`
	Module      string            `hcl:"module,attr" json:"module"`
	Config      map[string]string `hcl:"config,attr" json:"config"`
	MaxBodySize int64             `hcl:"max_body_size,attr" json:"max_body_size"`
	Access      []string          `hcl:"access,attr" json:"access"`
}

// Validate checks that module path is present and access capabilities are known.
func (w *Wasm) Validate() error {
	if w.Enabled.NotActive() {
		return nil
	}
	if w.Module == "" {
		return ErrModulePathRequired
	}
	for _, a := range w.Access {
		switch strings.ToLower(a) {
		case AccessHeaders, AccessBody, AccessMethod, AccessURI, AccessConfig:
		default:
			return errors.Newf("%w %q", ErrUnknownCapability, a)
		}
	}
	if w.MaxBodySize < 0 {
		return ErrNegativeBodySize
	}
	return nil
}

// HasAccess reports whether the given capability is in the access list.
func (w *Wasm) HasAccess(capability string) bool {
	for _, a := range w.Access {
		if strings.EqualFold(a, capability) {
			return true
		}
	}
	return false
}
