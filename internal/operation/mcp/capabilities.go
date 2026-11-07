// Package mcp implements the read/plan-only MCP control plane.
package mcp

// Class is the effect class of a capability. There is deliberately no apply
// class in v1.
type Class string

const (
	ClassRead Class = "read"
	ClassPlan Class = "plan"
)

// Capability maps a config-facing capability name to the MCP tool that
// implements it. validate/diff exist in both classes: the current config is
// read, a candidate config is plan.
type Capability struct {
	Name  string
	Class Class
	Tool  string
}

var Registry = []Capability{
	// read
	{Name: "status", Class: ClassRead, Tool: "agbero_status"},
	{Name: "system", Class: ClassRead, Tool: "agbero_system_info"},
	{Name: "config.global", Class: ClassRead, Tool: "agbero_config_get_global"},
	{Name: "config.hosts", Class: ClassRead, Tool: "agbero_config_list_hosts"},
	{Name: "config.host", Class: ClassRead, Tool: "agbero_config_get_host"},
	{Name: "config.effective", Class: ClassRead, Tool: "agbero_config_effective"},
	{Name: "config.explain", Class: ClassRead, Tool: "agbero_config_explain"},
	{Name: "config.validate", Class: ClassRead, Tool: "agbero_config_validate"},
	{Name: "config.diff", Class: ClassRead, Tool: "agbero_config_diff"},
	{Name: "routes.explain", Class: ClassRead, Tool: "agbero_routes_explain"},
	{Name: "security.review", Class: ClassRead, Tool: "agbero_security_review"},
	{Name: "certs.list", Class: ClassRead, Tool: "agbero_certs_list"},
	{Name: "firewall.list", Class: ClassRead, Tool: "agbero_firewall_list"},
	{Name: "cache.stats", Class: ClassRead, Tool: "agbero_cache_stats"},
	{Name: "cluster.status", Class: ClassRead, Tool: "agbero_cluster_status"},

	// plan
	{Name: "config.validate", Class: ClassPlan, Tool: "agbero_config_validate"},
	{Name: "config.diff", Class: ClassPlan, Tool: "agbero_config_diff"},
	{Name: "config.plan", Class: ClassPlan, Tool: "agbero_config_plan"},
}

// Lookup returns the capability entry for a class and name.
func Lookup(class Class, name string) (Capability, bool) {
	for _, c := range Registry {
		if c.Class == class && c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}

// Names returns the capability names registered for a class.
func Names(class Class) []string {
	out := make([]string, 0, len(Registry))
	for _, c := range Registry {
		if c.Class == class {
			out = append(out, c.Name)
		}
	}
	return out
}
