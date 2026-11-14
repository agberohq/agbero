package mcp

import "errors"

var ErrAdminPlane = errors.New("admin_plane_required")

// fieldCatalog is a small curated subset. Each entry is the shape
// agbero_config_explain returns.
var fieldCatalog = map[string]map[string]any{
	"host.compression": {
		"path": "host.compression", "type": "bool", "default": false,
		"valid": "true|false", "tier": "green",
		"security_impact": "low", "docs": "docs/host.md",
	},
	"route.rate_limit.requests": {
		"path": "route.rate_limit.requests", "type": "integer", "default": 100,
		"valid": "1..100000", "tier": "green",
		"security_impact": "tightening is safe; loosening can enable abuse",
		"docs":            "docs/host.md#rate-limit",
	},
	"route.timeouts": {
		"path": "route.timeouts", "type": "block", "tier": "green",
		"security_impact": "lower timeouts reduce resource exhaustion",
		"docs":            "docs/host.md#timeouts",
	},
	"route.health_check": {
		"path": "route.health_check", "type": "block", "tier": "green",
		"security_impact": "health checks affect failover only",
		"docs":            "docs/host.md#health-check",
	},
	"tls": {
		"path": "tls", "type": "block", "tier": "amber",
		"security_impact": "never downgrade TLS; renewal is an operation, not a field",
		"docs":            "docs/host.md#tls",
	},
	"route.backends": {
		"path": "route.backends", "type": "block", "tier": "amber",
		"security_impact": "adding a backend changes where traffic goes",
		"docs":            "docs/host.md#backend",
	},
	"route.path": {
		"path": "route.path", "type": "label", "tier": "amber",
		"security_impact": "path changes routing; the label is not a normal attribute",
		"docs":            "docs/host.md#route",
	},
	"logging.level": {
		"path": "logging.level", "type": "string", "tier": "amber",
		"security_impact": "can hide evidence; global field, not host-only",
		"docs":            "docs/global.md#logging",
	},
}

// FieldCatalog returns a copy of the field catalog.
func FieldCatalog() map[string]map[string]any {
	out := make(map[string]map[string]any, len(fieldCatalog))
	for k, v := range fieldCatalog {
		cp := make(map[string]any, len(v))
		for kk, vv := range v {
			cp[kk] = vv
		}
		out[k] = cp
	}
	return out
}
