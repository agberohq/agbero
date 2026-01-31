package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Admin struct {
	Address    string   `hcl:"address"` // e.g. ":9090"
	AllowedIPs []string `hcl:"allowed_ips,optional"`

	BasicAuth   *BasicAuth   `hcl:"basic_auth,block"`
	ForwardAuth *ForwardAuth `hcl:"forward_auth,block"`
	JWTAuth     *JWTAuth     `hcl:"jwt_auth,block"` // Now using struct
	OAuth       *OAuth       `hcl:"o_auth,block"`   // New
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
	if a.JWTAuth != nil {
		if err := a.JWTAuth.Validate(); err != nil {
			return errors.Newf("jwt_auth: %w", err)
		}
	}
	if a.OAuth != nil {
		if err := a.OAuth.Validate(); err != nil {
			return errors.Newf("o_auth: %w", err)
		}
	}
	return nil
}
