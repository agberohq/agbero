package alaye

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Admin struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Address    string        `hcl:"address,attr" json:"address"`
	AllowedIPs []string      `hcl:"allowed_ips,attr" json:"allowed_ips"`

	TOTP TOTP `hcl:"totp,block" json:"totp"`

	//BasicAuth BasicAuth `hcl:"basic_auth,block" json:"basic_auth"`
	//JWTAuth JWTAuth `hcl:"jwt_auth,block" json:"jwt_auth"`

	ForwardAuth ForwardAuth `hcl:"forward_auth,block" json:"forward_auth"`
	OAuth       OAuth       `hcl:"o_auth,block" json:"o_auth"`

	Pprof     Pprof     `hcl:"pprof,block" json:"pprof"`
	Telemetry Telemetry `hcl:"telemetry,block" json:"telemetry"`
}

func (a *Admin) Validate() error {
	if a.Enabled.NotActive() {
		return nil
	}

	if a.Address == "" {
		return def.ErrAdminAddressRequired
	}

	if _, _, err := net.SplitHostPort(a.Address); err != nil {
		if strings.HasPrefix(a.Address, ":") {
			if _, err := net.LookupPort(def.TCP, a.Address[1:]); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if err := a.Pprof.Validate(); err != nil {
		return errors.Newf("pprof: %w", err)
	}
	return nil
}
