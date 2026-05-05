package alaye

import (
	"net"
	"regexp"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Security struct {
	Enabled  expect.Toggle `hcl:"enabled,attr"          json:"enabled"`
	Allow    Allow         `hcl:"allow,block"        json:"allow"`
	Firewall Firewall      `hcl:"firewall,block"            json:"firewall"`
	WAF      WAF           `hcl:"waf,block"                 json:"waf"`
	Keeper   Keeper        `hcl:"keeper,block"              json:"keep"`
}

type Allow struct {
	Proxies  []string `hcl:"proxies,attr"  json:"proxies"`
	Commands []string `hcl:"commands,attr" json:"allowed_commands"`

	// ServerlessGit opts in to git-backed serverless workers.
	// Disabled by default: a compromised repository grants arbitrary code
	// execution on the host — the command allowlist cannot protect against
	// malicious scripts run by an allowed binary (e.g. "node evil.js").
	// Enable only when you trust every repository wired to a serverless git
	// block. A loud warning is printed at startup whenever this is active.
	ServerlessGit bool `hcl:"serverless_git,attr" json:"serverless_git"`
}

func (a Allow) IsZero() bool {
	return len(a.Proxies) == 0 && len(a.Commands) == 0 && !a.ServerlessGit
}

var allowedCommandRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

func (a Allow) Validate() error {
	for i, proxy := range a.Proxies {
		if _, _, err := net.ParseCIDR(proxy); err != nil {
			if ip := net.ParseIP(proxy); ip == nil {
				return errors.Newf("security: trusted_proxies[%d]=%q is invalid", i, proxy)
			}
		}
	}

	seen := make(map[string]bool, len(a.Commands))
	for _, cmd := range a.Commands {
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

// Validate checks trusted proxy formats and delegates to Firewall.Validate.
func (s *Security) Validate() error {
	if s == nil {
		return nil
	}
	if s.Enabled.NotActive() {
		return nil
	}
	if err := s.Firewall.Validate(); err != nil {
		return err
	}

	return s.WAF.Validate()
}
