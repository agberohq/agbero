package alaye

import (
	"net"
	"regexp"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

// MCP configures the read/plan-only MCP server. Apply is reserved and cannot
// be enabled.
type MCP struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Transport  string        `hcl:"transport,attr" json:"transport"` // stdio | unix
	Socket     string        `hcl:"socket,attr,omitempty" json:"socket,omitempty"`
	RateLimit  string        `hcl:"rate_limit,attr" json:"rate_limit"`
	AuditFile  string        `hcl:"audit_file,attr" json:"audit_file"`
	AllowedIPs []string      `hcl:"allowed_ips,attr,omitempty" json:"allowed_ips,omitempty"`

	Read  MCPRead  `hcl:"read,block" json:"read"`
	Plan  MCPPlan  `hcl:"plan,block" json:"plan"`
	Apply MCPApply `hcl:"apply,block,omitempty" json:"apply,omitempty"`
}

type MCPRead struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Allow   []string      `hcl:"allow,attr,omitempty" json:"allow,omitempty"`
	Deny    []string      `hcl:"deny,attr,omitempty" json:"deny,omitempty"`
	Hosts   []string      `hcl:"hosts,attr,omitempty" json:"hosts,omitempty"`
}

type MCPPlan struct {
	Enabled       expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Allow         []string      `hcl:"allow,attr,omitempty" json:"allow,omitempty"`
	Hosts         []string      `hcl:"hosts,attr,omitempty" json:"hosts,omitempty"`
	MaxInputBytes int64         `hcl:"max_input_bytes,attr,omitempty" json:"max_input_bytes,omitempty"`
}

// MCPApply is reserved for a future release. It is decoded so a config that
// enables it fails with a clear message instead of an unknown block.
type MCPApply struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	AllowTiers []string      `hcl:"allow_tiers,attr,omitempty" json:"allow_tiers,omitempty"`
	Hosts      []string      `hcl:"hosts,attr,omitempty" json:"hosts,omitempty"`
}

var (
	MCPReadCapabilities = []string{
		"status",
		"system",
		"config.global",
		"config.hosts",
		"config.host",
		"config.effective",
		"config.explain",
		"config.validate",
		"config.diff",
		"routes.explain",
		"security.review",
		"certs.list",
		"firewall.list",
		"cache.stats",
		"cluster.status",
	}
	MCPPlanCapabilities = []string{
		"config.validate",
		"config.diff",
		"config.plan",
	}
)

var mcpRateLimitPattern = regexp.MustCompile(`^[1-9][0-9]*/(s|m|h)$`)

// Validate enforces the read/plan contract. Defaults come from
// woos.defaultMCP, so an empty transport or rate_limit is accepted here.
func (m *MCP) Validate() error {
	if m == nil {
		return nil
	}

	if m.Enabled.NotActive() {
		if m.Read.Enabled.Active() || m.Plan.Enabled.Active() || m.Apply.Enabled.Active() {
			return errors.New("read/plan/apply cannot be enabled while mcp.enabled is off")
		}
		return nil
	}

	transport := strings.ToLower(strings.TrimSpace(m.Transport))
	if transport == "" {
		transport = "stdio"
	}
	switch transport {
	case "stdio", "unix":
	case "tcp", "http":
		return errors.Newf("transport %q is not supported in v1 (stdio or unix)", m.Transport)
	default:
		return errors.Newf("invalid transport %q (stdio or unix)", m.Transport)
	}

	rateLimit := strings.TrimSpace(m.RateLimit)
	if rateLimit == "" {
		rateLimit = "60/m"
	}
	if !mcpRateLimitPattern.MatchString(rateLimit) {
		return errors.Newf("invalid rate_limit %q (want e.g. 60/m)", m.RateLimit)
	}
	if err := validateMCPAllowedIPs(m.AllowedIPs); err != nil {
		return err
	}

	active := 0
	if m.Read.Enabled.Active() {
		active++
		if len(m.Read.Allow) == 0 {
			return errors.New("read.enabled is on but read.allow is empty")
		}
		if err := validateMCPAllow("read", m.Read.Allow, m.Read.Deny, MCPReadCapabilities); err != nil {
			return err
		}
		if err := validateMCPHosts("read", m.Read.Hosts, true); err != nil {
			return err
		}
	}
	if m.Plan.Enabled.Active() {
		active++
		if len(m.Plan.Allow) == 0 {
			return errors.New("plan.enabled is on but plan.allow is empty")
		}
		if err := validateMCPAllow("plan", m.Plan.Allow, nil, MCPPlanCapabilities); err != nil {
			return err
		}
		if err := validateMCPHosts("plan", m.Plan.Hosts, true); err != nil {
			return err
		}
		if m.Plan.MaxInputBytes < 0 {
			return errors.New("plan.max_input_bytes cannot be negative")
		}
		if m.Plan.MaxInputBytes > def.HostConfigMaxBytes {
			return errors.Newf("plan.max_input_bytes %d exceeds HostConfigMaxBytes (%d)",
				m.Plan.MaxInputBytes, def.HostConfigMaxBytes)
		}
	}
	if m.Apply.Enabled.Active() {
		return errors.New("apply is reserved and cannot be enabled in v1")
	}
	if active == 0 {
		return errors.New("mcp.enabled is on but no class (read/plan) is enabled")
	}
	return nil
}

func validateMCPAllow(class string, allow, deny, registry []string) error {
	known := make(map[string]struct{}, len(registry))
	for _, name := range registry {
		known[name] = struct{}{}
	}
	allowed := make(map[string]struct{}, len(allow))
	for i, raw := range allow {
		name := strings.TrimSpace(raw)
		if name == "" {
			return errors.Newf("%s.allow[%d] is empty", class, i)
		}
		if name == "*" {
			return errors.Newf("%s.allow[%d]: wildcard capabilities are not allowed", class, i)
		}
		if _, ok := known[name]; !ok {
			return errors.Newf("%s.allow[%d]: unknown capability %q", class, i, raw)
		}
		if _, dup := allowed[name]; dup {
			return errors.Newf("%s.allow[%d]: duplicate capability %q", class, i, raw)
		}
		allowed[name] = struct{}{}
	}
	for i, raw := range deny {
		name := strings.TrimSpace(raw)
		if name == "" {
			return errors.Newf("%s.deny[%d] is empty", class, i)
		}
		if _, ok := known[name]; !ok {
			return errors.Newf("%s.deny[%d]: unknown capability %q", class, i, raw)
		}
	}
	return nil
}

func validateMCPHosts(class string, hosts []string, allowAllWildcard bool) error {
	seen := make(map[string]struct{}, len(hosts))
	for i, raw := range hosts {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" {
			return errors.Newf("%s.hosts[%d] is empty", class, i)
		}
		if _, dup := seen[host]; dup {
			return errors.Newf("%s.hosts[%d]: duplicate host %q", class, i, raw)
		}
		seen[host] = struct{}{}

		switch {
		case host == "*":
			if !allowAllWildcard {
				return errors.Newf("%s.hosts[%d]: \"*\" is not allowed", class, i)
			}
		case strings.HasPrefix(host, "*."):
			if !allowAllWildcard {
				return errors.Newf("%s.hosts[%d]: wildcards are not allowed", class, i)
			}
			if _, err := expect.NewRaw(host[2:]).Domain(); err != nil {
				return errors.Newf("%s.hosts[%d]: %v", class, i, err)
			}
		default:
			if _, err := expect.NewRaw(host).Domain(); err != nil {
				return errors.Newf("%s.hosts[%d]: %v", class, i, err)
			}
		}
	}
	return nil
}

// validateMCPAllowedIPs checks the client IP allowlist. An explicit list
// replaces the loopback default, and catch-all ranges are rejected.
func validateMCPAllowedIPs(ips []string) error {
	seen := make(map[string]struct{}, len(ips))
	for i, raw := range ips {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return errors.Newf("allowed_ips[%d] is empty", i)
		}
		if strings.EqualFold(entry, "localhost") {
			canonical := "localhost"
			if _, dup := seen[canonical]; dup {
				return errors.Newf("allowed_ips[%d]: duplicate entry %q", i, entry)
			}
			seen[canonical] = struct{}{}
			continue
		}
		var canonical string
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return errors.Newf("allowed_ips[%d]: %v", i, err)
			}
			canonical = network.String()
			if canonical == "0.0.0.0/0" || canonical == "::/0" {
				return errors.Newf("allowed_ips[%d]: %q allows every address; list specific networks", i, entry)
			}
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return errors.Newf("allowed_ips[%d]: invalid IP %q (use an IP or CIDR; localhost is 127.0.0.1/32)", i, entry)
			}
			canonical = ip.String()
		}
		if _, dup := seen[canonical]; dup {
			return errors.Newf("allowed_ips[%d]: duplicate entry %q", i, entry)
		}
		seen[canonical] = struct{}{}
	}
	return nil
}
