package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// ReadDeps supplies daemon or offline data to the tools. Runtime callbacks may
// be nil in offline/stdin mode; those tools then fail with
// admin_plane_required instead of fabricating data.
type ReadDeps struct {
	Version   string
	Commit    string
	BuildDate string
	StartedAt time.Time

	KeeperLocked   func() bool
	ClusterMembers func() int
	AdminEnabled   bool
	Mode           string
	Offline        bool

	Global  *alaye.Global
	Hosts   func() (map[string]*alaye.Host, error)
	RawHost func(domain string) ([]byte, error)

	Certs        func(context.Context) (any, error)
	Firewall     func(context.Context) (any, error)
	CacheStats   func(context.Context) (any, error)
	ClusterState func(context.Context) (any, error)
}

type EmptyInput struct{}
type HostInput struct {
	Domain string `json:"domain" jsonschema:"host domain"`
}
type EffectiveInput struct {
	Scope  string `json:"scope,omitempty" jsonschema:"global, host, or route"`
	Domain string `json:"domain,omitempty" jsonschema:"host domain for host/route scope"`
	Route  string `json:"route,omitempty" jsonschema:"route path for route scope"`
}
type ValidateInput struct {
	Domain    string `json:"domain,omitempty" jsonschema:"current host domain"`
	Candidate string `json:"candidate,omitempty" jsonschema:"candidate HCL or JSON"`
	Format    string `json:"format,omitempty" jsonschema:"hcl or json"`
}
type DiffInput struct {
	Domain    string `json:"domain" jsonschema:"host domain"`
	Candidate string `json:"candidate,omitempty" jsonschema:"candidate HCL or JSON"`
	Against   string `json:"against,omitempty" jsonschema:"disk or live"`
}
type ExplainInput struct {
	Path    string `json:"path,omitempty" jsonschema:"field path"`
	Section string `json:"section,omitempty" jsonschema:"section name"`
}
type RoutesInput struct {
	Domain string `json:"domain" jsonschema:"host domain"`
	Path   string `json:"path,omitempty" jsonschema:"route path"`
}
type PatchOp struct {
	Op    string `json:"op" jsonschema:"add, replace, or remove"`
	Path  string `json:"path" jsonschema:"route[/api].field or host.field or top-level field"`
	Value any    `json:"value,omitempty"`
}

type PlanInput struct {
	Domain    string    `json:"domain" jsonschema:"host domain"`
	Intent    string    `json:"intent,omitempty" jsonschema:"short intent"`
	Candidate string    `json:"candidate,omitempty" jsonschema:"candidate HCL or JSON"`
	Patch     []PatchOp `json:"patch,omitempty" jsonschema:"structured patch operations"`
}

type StatusOutput struct {
	Version         string `json:"version"`
	Uptime          string `json:"uptime"`
	KeeperLocked    bool   `json:"keeper_locked"`
	ClusterMembers  int    `json:"cluster_members"`
	AdminEnabled    bool   `json:"admin_enabled"`
	ReloadSupported bool   `json:"reload_supported"`
	Mode            string `json:"mode"`
}

type SystemOutput struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// RegisterReadTools registers only the capabilities in the allow map.
func RegisterReadTools(server *sdk.Server, deps ReadDeps, allowed map[string]bool) {
	if allowed["status"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_status", Description: "Agbero runtime status. Read-only."}, deps.status)
	}
	if allowed["system"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_system_info", Description: "Agbero build information. Read-only."}, deps.system)
	}
	if allowed["config.global"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_get_global", Description: "Redacted global configuration."}, deps.getGlobal)
	}
	if allowed["config.hosts"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_list_hosts", Description: "Canonical host summaries."}, deps.listHosts)
	}
	if allowed["config.host"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_get_host", Description: "One redacted host configuration."}, deps.getHost)
	}
	if allowed["config.effective"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_effective", Description: "Effective global/host/route configuration."}, deps.effective)
	}
	if allowed["config.validate"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_validate", Description: "Validate current or candidate host config. No persistence."}, deps.validate)
	}
	if allowed["config.diff"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_diff", Description: "Semantic-ish diff between disk and a candidate. No persistence."}, deps.diff)
	}
	if allowed["config.explain"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_explain", Description: "Field documentation and security impact."}, deps.explain)
	}
	if allowed["routes.explain"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_routes_explain", Description: "Host route, backends, and middleware order."}, deps.routesExplain)
	}
	if allowed["security.review"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_security_review", Description: "Read-only posture findings."}, deps.securityReview)
	}
	if allowed["certs.list"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_certs_list", Description: "Certificate inventory (no private keys)."}, deps.certsList)
	}
	if allowed["firewall.list"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_firewall_list", Description: "Active firewall rules."}, deps.firewallList)
	}
	if allowed["cache.stats"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_cache_stats", Description: "Cache availability/counters."}, deps.cacheStats)
	}
	if allowed["cluster.status"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_cluster_status", Description: "Cluster members and counters."}, deps.clusterStatus)
	}
	if allowed["config.plan"] {
		sdk.AddTool(server, &sdk.Tool{Name: "agbero_config_plan", Description: "Compute a side-effect-free plan/diff for one host. A human applies it."}, deps.plan)
	}
}

func (d ReadDeps) status(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, StatusOutput, error) {
	if !d.authorized(ctx) {
		return nil, StatusOutput{}, ErrInvalidScope
	}
	locked := true
	if d.KeeperLocked != nil {
		locked = d.KeeperLocked()
	}
	members := 0
	if d.ClusterMembers != nil {
		members = d.ClusterMembers()
	}
	mode := d.Mode
	if mode == "" {
		mode = def.MCPModeDaemon
	}
	return nil, StatusOutput{
		Version: d.Version, Uptime: time.Since(d.StartedAt).Round(time.Second).String(),
		KeeperLocked: locked, ClusterMembers: members, AdminEnabled: d.AdminEnabled,
		ReloadSupported: true, Mode: mode,
	}, nil
}

func (d ReadDeps) system(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, SystemOutput, error) {
	if !d.authorized(ctx) {
		return nil, SystemOutput{}, ErrInvalidScope
	}
	return nil, SystemOutput{
		Version: d.Version, Commit: d.Commit, BuildDate: d.BuildDate,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}, nil
}

func (d ReadDeps) getGlobal(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	if d.Global == nil {
		return nil, nil, ErrAdminPlane
	}
	return nil, mustMap(alaye.RedactGlobal(d.Global)), nil
}

func (d ReadDeps) listHosts(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	hosts, err := d.hosts()
	if err != nil {
		return nil, nil, err
	}
	out := make([]map[string]any, 0, len(hosts))
	for canonical, h := range hosts {
		out = append(out, map[string]any{
			"canonical": canonical,
			"aliases":   h.Domains,
			"routes":    len(h.Routes),
			"proxies":   len(h.Proxies),
			"tls":       h.TLS.Mode,
			"protected": h.Protected.Active(),
		})
	}
	return nil, map[string]any{"hosts": out}, nil
}

func (d ReadDeps) getHost(ctx context.Context, _ *sdk.CallToolRequest, in HostInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	h, canonical, err := d.findHost(in.Domain)
	if err != nil {
		return nil, nil, err
	}
	red := alaye.RedactHost(h)
	return nil, map[string]any{
		"canonical": canonical,
		"aliases":   h.Domains,
		"protected": h.Protected.Active(),
		"source":    red,
		"effective": red,
	}, nil
}

func (d ReadDeps) effective(ctx context.Context, _ *sdk.CallToolRequest, in EffectiveInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	switch strings.ToLower(strings.TrimSpace(in.Scope)) {
	case "", "global":
		if d.Global == nil {
			return nil, nil, ErrAdminPlane
		}
		return nil, map[string]any{"scope": "global", "source": "effective", "value": mustMap(alaye.RedactGlobal(d.Global))}, nil
	case "host":
		h, canonical, err := d.findHost(in.Domain)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"scope": "host", "canonical": canonical, "source": "effective", "value": mustMap(alaye.RedactHost(h))}, nil
	case "route":
		h, _, err := d.findHost(in.Domain)
		if err != nil {
			return nil, nil, err
		}
		for _, r := range h.Routes {
			if r.Path == in.Route {
				return nil, map[string]any{"scope": "route", "path": r.Path, "source": "effective", "value": routeMap(r)}, nil
			}
		}
		return nil, nil, fmt.Errorf("route %q not found", in.Route)
	default:
		return nil, nil, fmt.Errorf("scope must be global, host, or route")
	}
}

func (d ReadDeps) validate(ctx context.Context, _ *sdk.CallToolRequest, in ValidateInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	var h *alaye.Host
	var err error
	switch {
	case strings.TrimSpace(in.Candidate) != "":
		format := strings.ToLower(strings.TrimSpace(in.Format))
		h, err = parseCandidate(in.Candidate, format)
	case strings.TrimSpace(in.Domain) != "":
		h, _, err = d.findHost(in.Domain)
	default:
		return nil, nil, fmt.Errorf("domain or candidate is required")
	}
	if err != nil {
		return nil, map[string]any{"valid": false, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error()}}}, nil
	}
	if err := h.Validate(); err != nil {
		return nil, map[string]any{"valid": false, "diagnostics": []map[string]any{{"severity": "error", "message": err.Error()}}}, nil
	}
	return nil, map[string]any{"valid": true, "diagnostics": []map[string]any{}}, nil
}

func (d ReadDeps) diff(ctx context.Context, _ *sdk.CallToolRequest, in DiffInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	if strings.TrimSpace(in.Candidate) == "" {
		return nil, nil, fmt.Errorf("candidate is required")
	}
	h, _, err := d.findHost(in.Domain)
	if err != nil {
		return nil, nil, err
	}
	candidate, err := parseCandidate(in.Candidate, "")
	if err != nil {
		return nil, nil, err
	}
	oldBytes, err := d.currentBytes(in.Domain, h)
	if err != nil {
		return nil, nil, err
	}
	newBytes, err := parser.MarshalBytes(alaye.RedactHost(candidate))
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{
		"diff":           textDiff(string(oldBytes), string(newBytes)),
		"base_revision":  sha256Hex(oldBytes),
		"candidate_hash": sha256Hex(newBytes),
	}, nil
}

func (d ReadDeps) explain(ctx context.Context, _ *sdk.CallToolRequest, in ExplainInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = strings.TrimSpace(in.Section)
	}
	entry, ok := fieldCatalog[path]
	if !ok {
		return nil, nil, fmt.Errorf("unknown field or section %q", path)
	}
	return nil, entry, nil
}

func (d ReadDeps) routesExplain(ctx context.Context, _ *sdk.CallToolRequest, in RoutesInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	h, canonical, err := d.findHost(in.Domain)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range h.Routes {
		if in.Path != "" && r.Path != in.Path {
			continue
		}
		servers := make([]string, 0, len(r.Backends.Servers))
		for _, s := range r.Backends.Servers {
			servers = append(servers, s.Address.String())
		}
		return nil, map[string]any{
			"canonical": canonical,
			"path":      r.Path,
			"backends":  servers,
			"strategy":  r.Backends.Strategy,
			"middleware": []string{
				"firewall", "waf", "rate_limit", "jwt_auth", "basic_auth",
				"forward_auth", "oauth", "cache", "compression", "headers",
			},
			"source": "config",
		}, nil
	}
	return nil, nil, fmt.Errorf("route %q not found", in.Path)
}

func (d ReadDeps) securityReview(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	if d.Global == nil {
		return nil, nil, ErrAdminPlane
	}
	g := d.Global
	var findings []map[string]any
	add := func(severity, check, evidence, why, remediation string) {
		findings = append(findings, map[string]any{
			"severity": severity, "check": check, "evidence": evidence,
			"why": why, "remediation": remediation,
		})
	}
	if g.Admin.Enabled.Active() && !isLoopbackAddr(g.Admin.Address) {
		add("high", "admin_non_loopback", g.Admin.Address, "admin plane is reachable beyond loopback", "bind admin to loopback or restrict allowed_ips")
	}
	if g.LetsEncrypt.Staging.Active() {
		add("low", "acme_staging", "letsencrypt.staging", "staging certificates are not publicly trusted", "disable staging for production")
	}
	if !g.Security.BlockPrivateBackends {
		add("medium", "ssrf_private_backends", "security.block_private_backends = false", "routes may reach private/metadata addresses", "enable block_private_backends")
	}
	if g.Security.Allow.ServerlessGit.Active() {
		add("high", "serverless_git", "serverless_git = true", "a compromised repository can execute code", "disable serverless_git")
	}
	if !g.Security.Firewall.Status.Active() {
		add("medium", "firewall_disabled", "security.firewall.enabled = false", "no automatic ban layer", "enable firewall")
	}
	hosts, err := d.hosts()
	if err == nil {
		for canonical, h := range hosts {
			for _, r := range h.Routes {
				if r.Web.Listing.Active() {
					add("medium", "directory_listing", canonical+" "+r.Path, "directory listing exposes files", "disable web.listing")
				}
				if r.Web.Root.IsSet() && (r.Web.Root.String() == "." || r.Web.Root.String() == "./") {
					add("medium", "web_root_dot", canonical+" "+r.Path, "serving the working directory can expose config", "set web.root to a dedicated directory")
				}
			}
		}
	}
	return nil, map[string]any{"findings": findings}, nil
}

func (d ReadDeps) certsList(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	return d.runtime(ctx, "certs", d.Certs)
}

func (d ReadDeps) firewallList(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	return d.runtime(ctx, "firewall", d.Firewall)
}

func (d ReadDeps) cacheStats(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	return d.runtime(ctx, "cache", d.CacheStats)
}

func (d ReadDeps) clusterStatus(ctx context.Context, _ *sdk.CallToolRequest, _ EmptyInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	return d.runtime(ctx, "cluster", d.ClusterState)
}

func (d ReadDeps) runtime(ctx context.Context, name string, fn func(context.Context) (any, error)) (*sdk.CallToolResult, any, error) {
	if fn == nil {
		return nil, nil, ErrAdminPlane
	}
	out, err := fn(ctx)
	if err != nil {
		return nil, nil, err
	}
	return nil, out, nil
}

func (d ReadDeps) plan(ctx context.Context, _ *sdk.CallToolRequest, in PlanInput) (*sdk.CallToolResult, any, error) {
	if !d.authorized(ctx) {
		return nil, nil, ErrInvalidScope
	}
	if !d.Offline && !HasScope(ClaimsFromContext(ctx), ScopePlan) {
		return nil, nil, ErrInvalidScope
	}
	h, canonical, err := d.findHost(in.Domain)
	if err != nil {
		return nil, nil, err
	}
	var candidate *alaye.Host
	var changes []map[string]any
	risk := "low"
	if strings.TrimSpace(in.Candidate) != "" {
		candidate, err = parseCandidate(in.Candidate, "")
		if err != nil {
			return nil, nil, err
		}
	} else if len(in.Patch) > 0 {
		candidate, changes, risk, err = applyPlanPatch(h, in.Patch)
		if err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, fmt.Errorf("candidate or patch is required")
	}
	if err := candidate.Validate(); err != nil {
		return nil, nil, err
	}
	oldBytes, err := d.currentBytes(in.Domain, h)
	if err != nil {
		return nil, nil, err
	}
	newBytes, err := parser.MarshalBytes(alaye.RedactHost(candidate))
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{
		"canonical":        canonical,
		"intent":           in.Intent,
		"base_revision":    sha256Hex(oldBytes),
		"candidate_hash":   sha256Hex(newBytes),
		"diff":             textDiff(string(oldBytes), string(newBytes)),
		"semantic_changes": changes,
		"risk":             risk,
		"persisted":        false,
	}, nil
}

func (d ReadDeps) authorized(ctx context.Context) bool {
	return d.Offline || readScope(ctx)
}

func (d ReadDeps) hosts() (map[string]*alaye.Host, error) {
	if d.Hosts == nil {
		return nil, ErrAdminPlane
	}
	return d.Hosts()
}

func (d ReadDeps) findHost(domain string) (*alaye.Host, string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, "", fmt.Errorf("domain is required")
	}
	hosts, err := d.hosts()
	if err != nil {
		return nil, "", err
	}
	if h, ok := hosts[domain]; ok {
		return h, domain, nil
	}
	for canonical, h := range hosts {
		for _, alias := range h.Domains {
			if strings.EqualFold(alias, domain) {
				return h, canonical, nil
			}
		}
	}
	return nil, "", fmt.Errorf("host %q not found", domain)
}

func (d ReadDeps) currentBytes(domain string, h *alaye.Host) ([]byte, error) {
	return parser.MarshalBytes(alaye.RedactHost(h))
}

func parseCandidate(raw, format string) (*alaye.Host, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "hcl"
	}
	if format == "json" {
		var h alaye.Host
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			return nil, err
		}
		woos.DefaultHost(&h)
		return &h, nil
	}
	f, err := os.CreateTemp("", "agbero-mcp-*.hcl")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.WriteString(raw); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	h, err := parser.ParseHostConfig(name)
	if err != nil {
		return nil, err
	}
	woos.DefaultHost(h)
	return h, nil
}

func mustMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return out
}

func routeMap(r alaye.Route) map[string]any {
	b, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func textDiff(oldText, newText string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(oldText, newText, false)
	dmp.DiffCleanupSemantic(diffs)
	return dmp.DiffPrettyText(diffs)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var planRedPrefixes = []string{
	"bind", "admin", "api", "security", "waf", "firewall", "keeper", "secrets",
	"gossip", "storage", "serverless", "wasm", "tunnel", "git", "proxies",
	"version", "mcp", "logging.file", "logging.victoria", "logging.prometheus",
}

var planAmberPrefixes = []string{
	"tls", "domains", "limits", "cors", "waf", "rewrite",
	"strip_prefixes", "logging.level", "route.backends", "route.path",
	"route.cors", "route.waf", "route.strip_prefixes", "route.rewrites",
}

func planTier(path string) string {
	p := strings.ToLower(strings.TrimSpace(path))
	for _, prefix := range planRedPrefixes {
		if strings.HasPrefix(p, prefix) {
			return "red"
		}
	}
	if strings.HasPrefix(p, "route[") {
		for _, amber := range []string{".backends", ".path", ".cors", ".waf", ".strip_prefixes", ".rewrites"} {
			if strings.Contains(p, amber) {
				return "amber"
			}
		}
		if strings.HasSuffix(p, "].enabled") {
			return "amber"
		}
		return "green"
	}
	for _, prefix := range planAmberPrefixes {
		if strings.HasPrefix(p, prefix) {
			return "amber"
		}
	}
	return "green"
}

func applyPlanPatch(h *alaye.Host, ops []PatchOp) (*alaye.Host, []map[string]any, string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return nil, nil, "", err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, nil, "", err
	}
	var changes []map[string]any
	risk := "low"
	for i, op := range ops {
		opName := strings.ToLower(strings.TrimSpace(op.Op))
		switch opName {
		case "add", "replace", "remove":
		default:
			return nil, nil, "", fmt.Errorf("patch[%d]: op must be add, replace, or remove", i)
		}
		path := strings.TrimSpace(op.Path)
		if path == "" {
			return nil, nil, "", fmt.Errorf("patch[%d]: path is required", i)
		}
		tier := planTier(path)
		if tier == "red" {
			return nil, nil, "", fmt.Errorf("patch[%d]: %s is red-tier; MCP cannot plan it", i, path)
		}
		if tier == "amber" {
			risk = "medium"
		}
		old, err := patchGet(root, path)
		if err != nil {
			return nil, nil, "", fmt.Errorf("patch[%d]: %w", i, err)
		}
		if opName == "remove" {
			if err := patchRemove(root, path); err != nil {
				return nil, nil, "", fmt.Errorf("patch[%d]: %w", i, err)
			}
		} else {
			if err := patchSet(root, path, op.Value); err != nil {
				return nil, nil, "", fmt.Errorf("patch[%d]: %w", i, err)
			}
		}
		changes = append(changes, map[string]any{
			"op": opName, "path": path, "from": old, "to": op.Value, "tier": tier,
		})
	}
	patched, err := json.Marshal(root)
	if err != nil {
		return nil, nil, "", err
	}
	var out alaye.Host
	if err := json.Unmarshal(patched, &out); err != nil {
		return nil, nil, "", err
	}
	woos.DefaultHost(&out)
	return &out, changes, risk, nil
}

func patchParts(path string) ([]string, error) {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "host.")
	if strings.HasPrefix(path, "route[") {
		end := strings.Index(path, "]")
		if end < 0 {
			return nil, fmt.Errorf("unterminated route[ path")
		}
		routePath := strings.TrimSpace(path[len("route["):end])
		rest := strings.TrimPrefix(path[end+1:], ".")
		parts := []string{"routes"}
		// The route index is resolved by path equality in patchGet/Set.
		parts = append(parts, "path="+routePath)
		if rest != "" {
			parts = append(parts, strings.Split(rest, ".")...)
		}
		return parts, nil
	}
	return strings.Split(path, "."), nil
}

func patchGet(root map[string]any, path string) (any, error) {
	parts, err := patchParts(path)
	if err != nil {
		return nil, err
	}
	cur := any(root)
	for i, part := range parts {
		if strings.HasPrefix(part, "path=") {
			want := strings.TrimPrefix(part, "path=")
			arr, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("route path used without a routes array")
			}
			found := false
			for _, item := range arr {
				m, ok := item.(map[string]any)
				if ok && m["path"] == want {
					cur = m
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("route %q not found", want)
			}
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not an object", strings.Join(parts[:i], "."))
		}
		cur = m[part]
	}
	return cur, nil
}

func patchSet(root map[string]any, path string, value any) error {
	parts, err := patchParts(path)
	if err != nil {
		return err
	}
	parent, key, err := patchParent(root, parts)
	if err != nil {
		return err
	}
	parent[key] = value
	return nil
}

func patchRemove(root map[string]any, path string) error {
	parts, err := patchParts(path)
	if err != nil {
		return err
	}
	parent, key, err := patchParent(root, parts)
	if err != nil {
		return err
	}
	delete(parent, key)
	return nil
}

func patchParent(root map[string]any, parts []string) (map[string]any, string, error) {
	cur := any(root)
	for i, part := range parts {
		if i == len(parts)-1 {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, "", fmt.Errorf("parent of %q is not an object", part)
			}
			return m, part, nil
		}
		if strings.HasPrefix(part, "path=") {
			want := strings.TrimPrefix(part, "path=")
			arr, ok := cur.([]any)
			if !ok {
				return nil, "", fmt.Errorf("route path used without a routes array")
			}
			found := false
			for _, item := range arr {
				m, ok := item.(map[string]any)
				if ok && m["path"] == want {
					cur = m
					found = true
					break
				}
			}
			if !found {
				return nil, "", fmt.Errorf("route %q not found", want)
			}
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("%q is not an object", part)
		}
		next, ok := m[part]
		if !ok || next == nil {
			m[part] = map[string]any{}
			next = m[part]
		}
		cur = next
	}
	return nil, "", fmt.Errorf("empty path")
}
