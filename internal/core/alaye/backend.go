package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
)

type Backend struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Strategy string        `hcl:"strategy,attr,omitempty" json:"strategy,omitempty"`
	Keys     []string      `hcl:"keys,attr,omitempty" json:"keys,omitempty"`

	Servers []Server `hcl:"server,block" json:"servers"`
}

func (b Backend) IsZero() bool {
	return b.Enabled.IsZero() &&
		b.Strategy == "" &&
		len(b.Keys) == 0 &&
		len(b.Servers) == 0
}
