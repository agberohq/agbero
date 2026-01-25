package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Bind struct {
	HTTP  []string `hcl:"http,optional"`
	HTTPS []string `hcl:"https,optional"`
	Admin *Admin   `hcl:"admin,block"`
}

func (b *Bind) Validate() error {
	if len(b.HTTP) == 0 && len(b.HTTPS) == 0 {
		return errors.New("at least one of 'http' or 'https' bind addresses must be configured")
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

	if b.Admin != nil {
		if err := b.Admin.Validate(); err != nil {
			return errors.Newf("admin: %w", err)
		}
	}

	return nil
}

func (b *Bind) validateAddress(addr string) error {
	if addr == "" {
		return errors.New("address cannot be empty")
	}
	if strings.HasPrefix(addr, ":") {
		if _, err := net.LookupPort("tcp", addr[1:]); err != nil {
			return err
		}
		return nil
	}
	_, _, err := net.SplitHostPort(addr)
	return err
}

type Admin struct {
	Address     string       `hcl:"address"` // e.g. ":9090"
	BasicAuth   *BasicAuth   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block"`
}

func (a *Admin) Validate() error {
	if a.Address == "" {
		return errors.New("admin address is required")
	}
	if _, _, err := net.SplitHostPort(a.Address); err != nil {
		// Try parsing as port only
		if strings.HasPrefix(a.Address, ":") {
			if _, err := net.LookupPort("tcp", a.Address[1:]); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if a.BasicAuth != nil {
		if err := a.BasicAuth.Validate(); err != nil {
			return errors.Newf("basic_auth: %w", err)
		}
	}
	if a.ForwardAuth != nil {
		if err := a.ForwardAuth.Validate(); err != nil {
			return errors.Newf("forward_auth: %w", err)
		}
	}
	return nil
}
