package alaye

import (
	"net"
	"regexp"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Security struct {
	Enabled         expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	TrustedProxies  []string      `hcl:"trusted_proxies,attr" json:"trusted_proxies"`
	AllowedCommands []string      `hcl:"allowed_commands,attr" json:"allowed_commands"`
	Firewall        Firewall      `hcl:"firewall,block" json:"firewall"`
	Keeper          Keeper        `hcl:"keeper,block" json:"keep"`
}

// Validate checks trusted proxy formats and delegates to Firewall.Validate.
func (s *Security) Validate() error {
	if s == nil {
		return nil
	}
	if s.Enabled.NotActive() {
		return nil
	}
	for i, proxy := range s.TrustedProxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("security: trusted_proxies[%d]=%q is invalid", i, proxy)
			}
		}
	}
	return s.Firewall.Validate()
}

var allowedCommandRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// ValidateAllowedCommands checks every entry in the allowlist.
// Called from Security.Validate().
func ValidateAllowedCommands(cmds []string) error {
	seen := make(map[string]bool, len(cmds))
	for _, cmd := range cmds {
		if !allowedCommandRe.MatchString(cmd) {
			return errors.Newf(
				"security: allowed_commands: %q is invalid — must match ^[a-z][a-z0-9_-]*$ (bare lowercase name, no path, no dots)",
				cmd,
			)
		}
		if seen[cmd] {
			return errors.Newf("security: allowed_commands: duplicate entry %q", cmd)
		}
		seen[cmd] = true
	}
	return nil
}
