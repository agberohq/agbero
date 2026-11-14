// Package scan contains read-only configuration and host-posture checks.
// It never mutates config, files, or Keeper state.
package scan

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
)

type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

type Finding struct {
	Severity    Severity `json:"severity"`
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type Paths struct {
	ConfigFile           string `json:"config_file"`
	Home                 string `json:"home"`
	DataDir              string `json:"data_dir"`
	CertsDir             string `json:"certs_dir"`
	HostsDir             string `json:"hosts_dir"`
	LogFile              string `json:"log_file"`
	WorkDir              string `json:"work_dir"`
	KeeperPassphraseFile string `json:"keeper_passphrase_file"`
	KeeperDB             string `json:"keeper_db"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Paths       Paths     `json:"paths"`
	Findings    []Finding `json:"findings"`
}

func Run(g *alaye.Global, hosts map[string]*alaye.Host, paths Paths) Report {
	r := Report{GeneratedAt: time.Now().UTC(), Paths: paths}
	if g == nil {
		r.add(High, "config.missing", "No global configuration was loaded", "", "run `agbero config validate`")
		return r
	}
	if err := g.Validate(); err != nil {
		r.add(High, "config.invalid", "Global configuration does not validate", err.Error(), "fix the reported configuration error")
	}
	r.checkAdmin(g)
	r.checkSecurity(g)
	r.checkStorage(g, paths)
	r.checkHosts(g, hosts)
	r.checkMCP(g)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return rank(r.Findings[i].Severity) > rank(r.Findings[j].Severity)
	})
	return r
}

func (r *Report) add(s Severity, code, message, evidence, fix string) {
	r.Findings = append(r.Findings, Finding{Severity: s, Code: code, Message: message, Evidence: evidence, Remediation: fix})
}

func (r *Report) checkAdmin(g *alaye.Global) {
	if !g.Admin.Enabled.Active() {
		r.add(Low, "admin.disabled", "Admin plane is disabled", "admin.enabled = off", "enable the admin plane if you need UI/token/MCP management")
		return
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(g.Admin.Address))
	if err == nil && host != "" && !isLoopback(host) {
		r.add(High, "admin.exposed", "Admin listener is not bound to loopback", g.Admin.Address, "bind admin to 127.0.0.1 or restrict it with a firewall/allowlist")
	}
	if len(g.Admin.AllowedIPs) == 0 {
		r.add(Medium, "admin.allowlist.empty", "Admin allowlist is empty", "admin.allowed_ips = []", "restrict admin.allowed_ips to trusted networks")
	}
	if broadCIDR(g.Admin.AllowedIPs) {
		r.add(High, "admin.allowlist.broad", "Admin allowlist accepts every address", strings.Join(g.Admin.AllowedIPs, ", "), "replace 0.0.0.0/0 or ::/0 with trusted CIDRs")
	}
	if g.Admin.Pprof.Enabled.Active() {
		r.add(Medium, "admin.pprof", "pprof is enabled", g.Admin.Pprof.Bind, "disable pprof on production systems")
	}
}

func (r *Report) checkSecurity(g *alaye.Global) {
	if g.Security.Allow.ServerlessGit.Active() {
		r.add(High, "security.serverless_git", "Serverless Git can execute repository code", "security.allow.serverless_git = on", "disable it unless every repository is trusted")
	}
	if !g.Security.BlockPrivateBackends {
		r.add(Medium, "security.private_backends", "Private/loopback backends are allowed", "security.block_private_backends = false", "enable SSRF protection with block_private_backends = true")
	}
	if !g.Security.Firewall.Status.Active() {
		r.add(Medium, "security.firewall.disabled", "Automatic firewall is disabled", "security.firewall.enabled = off", "enable the firewall or provide an external WAF/ban layer")
	}
	if !g.Security.WAF.Status.Active() {
		r.add(Low, "security.waf.disabled", "WAF is disabled", "security.waf.enabled = off", "enable a WAF profile when handling untrusted HTTP traffic")
	}
	if g.LetsEncrypt.Staging.Active() {
		r.add(Low, "tls.acme_staging", "Let's Encrypt staging is enabled", "letsencrypt.staging = on", "disable staging before serving public traffic")
	}
	if g.Development {
		r.add(Low, "config.development", "Development mode is enabled", "development = true", "disable development mode in production")
	}
	raw := strings.TrimSpace(string(g.Security.Keeper.Passphrase))
	if raw != "" && !g.Security.Keeper.Passphrase.IsSecretStoreRef() && !strings.HasPrefix(strings.ToLower(raw), "env.") {
		r.add(High, "keeper.passphrase.plaintext", "Keeper passphrase appears to be stored in HCL", "<redacted>", "use passphrase_file, env.AGBERO_KEEPER_PASSPHRASE, or a keeper reference")
	}
}

func (r *Report) checkStorage(g *alaye.Global, p Paths) {
	checkMode := func(label, path string, want os.FileMode, worldSensitive bool) {
		if path == "" {
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			r.add(Medium, "storage."+label+".missing", label+" is missing", path, "verify the configured path and permissions")
			return
		}
		perm := info.Mode().Perm()
		if perm&want != 0 {
			r.add(High, "storage."+label+".permissions", label+" permissions are too open", fmt.Sprintf("%s (%04o)", path, perm), "restrict to the agbero service user")
		}
		if worldSensitive && perm&0004 != 0 {
			r.add(High, "storage."+label+".world_readable", label+" is world-readable", fmt.Sprintf("%s (%04o)", path, perm), "remove world permissions")
		}
	}
	checkMode("config", p.ConfigFile, 0077, true)
	if p.KeeperPassphraseFile != "" {
		if _, err := os.Stat(p.KeeperPassphraseFile); err == nil {
			r.add(High, "keeper.passphrase.file", "Keeper passphrase is stored next to the Keeper database", p.KeeperPassphraseFile, "move it to a systemd credential, Vault, or manual unlock and delete the file")
		}
	}
	checkMode("passphrase", p.KeeperPassphraseFile, 0077, true)
	checkMode("keeper_db", p.KeeperDB, 0077, true)
	checkMode("data", p.DataDir, 0002, false)
	checkMode("certs", p.CertsDir, 0002, false)
	checkMode("hosts", p.HostsDir, 0002, false)
	checkMode("work", p.WorkDir, 0002, false)

	if g.Security.Keeper.Enabled.Active() && p.KeeperPassphraseFile == "" && strings.TrimSpace(string(g.Security.Keeper.Passphrase)) == "" {
		r.add(Medium, "keeper.passphrase.missing", "Keeper is enabled but no passphrase source was configured", "keeper.passphrase and keeper.passphrase_file are empty", "set passphrase_file or AGBERO_KEEPER_PASSPHRASE for the service")
	}
	if p.LogFile != "" {
		if info, err := os.Stat(p.LogFile); err == nil && info.Mode().Perm()&0002 != 0 {
			r.add(Medium, "storage.logs.writable", "Log file is world-writable", p.LogFile, "remove world write permission")
		}
	}
}

func (r *Report) checkHosts(g *alaye.Global, hosts map[string]*alaye.Host) {
	if len(hosts) == 0 {
		r.add(Medium, "hosts.empty", "No hosts are configured", "", "add a host with `agbero host add`")
		return
	}
	seen := map[string]string{}
	for canonical, h := range hosts {
		if h == nil {
			continue
		}
		if err := h.Validate(); err != nil {
			r.add(High, "host.invalid", "Host configuration does not validate", canonical+": "+err.Error(), "fix the host configuration")
		}
		names := append([]string{canonical}, h.Domains...)
		for _, name := range names {
			key := strings.ToLower(strings.TrimSpace(name))
			if key == "" {
				continue
			}
			if prev, ok := seen[key]; ok && prev != canonical {
				r.add(Medium, "hosts.duplicate_domain", "Domain is claimed by more than one host", key+" ("+prev+" and "+canonical+")", "remove the duplicate domain/alias")
			}
			seen[key] = canonical
		}
		if h.TLS.Mode == def.ModeLocalNone {
			r.add(Medium, "host.tls.disabled", "Host has TLS disabled", canonical, "enable TLS for public hosts")
		}
		for _, route := range h.Routes {
			if route.Web.Enabled.Active() && route.Web.Root.String() == "." {
				r.add(High, "host.web_root.dot", "A web route serves the working directory", canonical+" "+route.Path, "set web.root to a dedicated directory")
			}
			if route.Web.Enabled.Active() && route.Web.Listing.Active() {
				r.add(Medium, "host.directory_listing", "Directory listing is enabled", canonical+" "+route.Path, "disable web.listing")
			}
			if !g.Security.BlockPrivateBackends {
				for _, srv := range route.Backends.Servers {
					if isPrivateAddress(srv.Address.String()) {
						r.add(Medium, "host.private_backend", "Route points at a private/loopback backend", canonical+" "+route.Path+" -> "+srv.Address.String(), "enable block_private_backends or add explicit egress controls")
					}
				}
			}
		}
	}
}

func (r *Report) checkMCP(g *alaye.Global) {
	if !g.MCP.Enabled.Active() {
		return
	}
	if broadCIDR(g.MCP.AllowedIPs) {
		r.add(High, "mcp.allowlist.broad", "MCP allows every address", strings.Join(g.MCP.AllowedIPs, ", "), "restrict mcp.allowed_ips")
	}
	if g.MCP.RateLimit == "" {
		r.add(Low, "mcp.rate_limit.missing", "MCP rate limit is empty", "", "set mcp.rate_limit")
	}
	if g.MCP.AuditFile == "" {
		r.add(Low, "mcp.audit.default", "MCP audit uses the default data-directory file", "", "set mcp.audit_file if you need a dedicated audit destination")
	}
	if g.MCP.Read.Enabled.Active() && len(g.MCP.Read.Allow) == 0 {
		r.add(Medium, "mcp.read.empty", "MCP read class is enabled without capabilities", "", "allow only the capabilities you need")
	}
}

func rank(s Severity) int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	default:
		return 1
	}
}

func isLoopback(s string) bool {
	if strings.EqualFold(s, "localhost") {
		return true
	}
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

func broadCIDR(ips []string) bool {
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		if raw == "0.0.0.0/0" || raw == "::/0" {
			return true
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			ones, bits := n.Mask.Size()
			if ones == 0 && bits > 0 {
				return true
			}
		}
	}
	return false
}

func isPrivateAddress(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	} else if strings.Contains(raw, "/") {
		host = strings.SplitN(raw, "/", 2)[0]
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func LogPath(g *alaye.Global, dataDir string) string {
	if g != nil && strings.TrimSpace(g.Logging.File.Path) != "" {
		return g.Logging.File.Path
	}
	return filepath.Join(dataDir, "logs.d")
}
