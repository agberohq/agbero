package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Bind struct {
	HTTP     []string `hcl:"http,optional" json:"http"`
	HTTPS    []string `hcl:"https,optional" json:"https"`
	Redirect Enabled  `hcl:"redirect,optional" json:"redirect"`
}

func (b *Bind) Validate() error {
	if len(b.HTTP) == 0 && len(b.HTTPS) == 0 {
		return ErrNoBindAddresses
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
		return ErrEmptyAddress
	}
	if strings.HasPrefix(addr, ":") {
		if _, err := net.LookupPort(TCP, addr[1:]); err != nil {
			return err
		}
		return nil
	}
	_, _, err := net.SplitHostPort(addr)
	return err
}
