package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type API struct {
	Enabled    Enabled  `hcl:"enabled,attr" json:"enabled"`
	Address    string   `hcl:"address,attr" json:"address"`
	AllowedIPs []string `hcl:"allowed_ips,attr" json:"allowed_ips"`
}

// Validate checks that the API block address is well-formed when enabled.
// Port-only addresses starting with ':' are accepted as valid.
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

	return nil
}
