package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Admin struct {
	Enabled    Enabled  `hcl:"enabled,attr" json:"enabled"`
	Pprof      Enabled  `hcl:"pprof,attr" json:"pprof"`
	Address    string   `hcl:"address,attr" json:"address"`
	AllowedIPs []string `hcl:"allowed_ips,attr" json:"allowed_ips"`

	BasicAuth   BasicAuth   `hcl:"basic_auth,block" json:"basic_auth"`
	ForwardAuth ForwardAuth `hcl:"forward_auth,block" json:"forward_auth"`
	JWTAuth     JWTAuth     `hcl:"jwt_auth,block" json:"jwt_auth"`
	OAuth       OAuth       `hcl:"o_auth,block" json:"o_auth"`
}

// Validate checks that the admin block is correctly configured when enabled.
// It verifies the address format and delegates auth block validation.
func (a *Admin) Validate() error {
	if a.Enabled.NotActive() {
		return nil
	}

	if a.Address == "" {
		return ErrAdminAddressRequired
	}

	if _, _, err := net.SplitHostPort(a.Address); err != nil {
		if strings.HasPrefix(a.Address, ":") {
			if _, err := net.LookupPort(TCP, a.Address[1:]); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if err := a.BasicAuth.Validate(); err != nil {
		return errors.Newf("basic_auth: %w", err)
	}

	if err := a.ForwardAuth.Validate(); err != nil {
		return errors.Newf("forward_auth: %w", err)
	}

	if err := a.JWTAuth.Validate(); err != nil {
		return errors.Newf("jwt_auth: %w", err)
	}

	if err := a.OAuth.Validate(); err != nil {
		return errors.Newf("o_auth: %w", err)
	}

	return nil
}
