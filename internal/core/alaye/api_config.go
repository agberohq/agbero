package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type API struct {
	Enabled        Enabled  `hcl:"enabled,optional" json:"enabled"`
	Address        string   `hcl:"address,optional" json:"address"` // e.g. ":9091"
	PrivateKeyFile string   `hcl:"private_key_file,optional" json:"private_key_file"`
	AllowedIPs     []string `hcl:"allowed_ips,optional" json:"allowed_ips"`
}

func (a *API) Validate() error {
	if a.Enabled.NotActive() {
		return nil
	}

	if a.Address == "" {
		return errors.New("api: address is required")
	}

	if _, _, err := net.SplitHostPort(a.Address); err != nil {
		if strings.HasPrefix(a.Address, ":") {
			if _, err := net.LookupPort("tcp", a.Address[1:]); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if a.PrivateKeyFile == "" {
		return errors.New("api: private_key_file is required for token verification")
	}

	return nil
}
