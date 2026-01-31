package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Admin struct {
	Address     string       `hcl:"address"` // e.g. ":9090"
	BasicAuth   *BasicAuth   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block"`
}

func (a *Admin) Validate() error {
	if a == nil {
		return nil
	}
	if a.Address == "" {
		return ErrAdminAddressRequired
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
