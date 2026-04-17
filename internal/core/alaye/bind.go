package alaye

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Bind struct {
	HTTP     []string      `hcl:"http,attr" json:"http"`
	HTTPS    []string      `hcl:"https,attr" json:"https"`
	Redirect expect.Toggle `hcl:"redirect,attr" json:"redirect"`
}

// Validate checks that at least one HTTP or HTTPS address is configured.
// Each address must be a valid host:port or port-only string.
func (b *Bind) Validate() error {
	if len(b.HTTP) == 0 && len(b.HTTPS) == 0 {
		return def.ErrNoBindAddresses
	}

	for i, addr := range b.HTTP {
		if err := b.validateAddress(addr); err != nil {
			return errors.Newf("http[%d]: %w", i, err)
		}
	}

	for i, addr := range b.HTTPS {
		if err := b.validateAddress(addr); err != nil {
			return errors.Newf("https[%d]: %w", i, err)
		}
	}

	return nil
}

func (b *Bind) validateAddress(addr string) error {
	if addr == "" {
		return def.ErrEmptyAddress
	}
	if strings.HasPrefix(addr, ":") {
		if _, err := net.LookupPort(def.TCP, addr[1:]); err != nil {
			return err
		}
		return nil
	}
	_, _, err := net.SplitHostPort(addr)
	return err
}
