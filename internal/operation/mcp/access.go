package mcp

import (
	"net/http"
	"strings"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/middleware/ipallow"
	"github.com/olekukonko/ll"
)

// DefaultAllowedIPs is the loopback-only default. An explicit mcp.allowed_ips
// list replaces it, so LAN deployments must include loopback to keep local CLI
// access.
var DefaultAllowedIPs = []string{"127.0.0.1/32", "::1/128"}

// AllowedIPs wraps an MCP handler with the configured client-IP allowlist. Pass
// the same trusted-proxy-aware IPManager the admin plane uses.
func AllowedIPs(allowed []string, logger *ll.Logger, ipMgr *zulu.IPManager) func(http.Handler) http.Handler {
	if len(allowed) == 0 {
		allowed = DefaultAllowedIPs
	}
	expanded := make([]string, 0, len(allowed)+1)
	for _, entry := range allowed {
		if strings.EqualFold(strings.TrimSpace(entry), "localhost") {
			expanded = append(expanded, "127.0.0.1/32", "::1/128")
			continue
		}
		expanded = append(expanded, entry)
	}
	return ipallow.New(expanded, logger, ipMgr)
}
