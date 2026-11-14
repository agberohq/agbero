package mcp

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

// MCPHostMarker marks the generated mcp.localhost host as page-managed.
const MCPHostMarker = "# Managed by Agbero from the MCP admin page."

// AdminBackendURL returns the loopback URL for the admin listener's MCP
// handler. The trailing slash plus MCPLocalhostConfig's route "/" means every
// request to https://mcp.localhost lands on /mcp/ and never on the rest of the
// admin surface.
func AdminBackendURL(adminAddr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(adminAddr))
	if err != nil || port == "" {
		return "http://127.0.0.1:9090/mcp/"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/mcp/"
}

// AdminMCPURL is the direct loopback MCP endpoint (no trailing slash).
func AdminMCPURL(adminAddr string) string {
	return strings.TrimSuffix(AdminBackendURL(adminAddr), "/")
}

func mcpHostAllowedIPs(allowed []string) []string {
	if len(allowed) == 0 {
		allowed = DefaultAllowedIPs
	}
	out := make([]string, 0, len(allowed)+2)
	for _, entry := range allowed {
		entry = strings.TrimSpace(entry)
		if strings.EqualFold(entry, "localhost") {
			out = append(out, "127.0.0.1/32", "::1/128")
			continue
		}
		if entry != "" {
			out = append(out, entry)
		}
	}
	if len(out) == 0 {
		out = append(out, DefaultAllowedIPs...)
	}
	return out
}

// MCPLocalhostConfig renders the optional https://mcp.localhost host. The
// backend path is /mcp/ so even the root request lands on the MCP handler.
func MCPLocalhostConfig(adminAddr string, allowed []string) []byte {
	ips := mcpHostAllowedIPs(allowed)
	var quoted []string
	for _, ip := range ips {
		quoted = append(quoted, fmt.Sprintf("%q", ip))
	}
	return []byte(fmt.Sprintf(`%s
domains = [%q]
protected = "off"

tls {
  mode = "auto"
}

route "/" {
  enabled  = "on"
  protocol = %q

  allowed_ips = [%s]

  backend {
    server {
      address = %q
      streaming { enabled = true }
    }
  }
}
`, MCPHostMarker, def.MCPLocalhostHost, def.RouteProtocolMCP, strings.Join(quoted, ", "), AdminBackendURL(adminAddr)))
}

// WriteMCPLocalhost creates hosts.d/mcp.localhost.hcl once. It never
// overwrites an existing host, and validates the generated HCL before the
// atomic rename.
func WriteMCPLocalhost(hostsDir expect.Folder, adminAddr string, allowed []string) (string, bool, error) {
	path := hostsDir.FilePath(def.MCPLocalhostHost + ".hcl")
	if _, err := os.Stat(path); err == nil {
		return path, false, nil
	} else if !os.IsNotExist(err) {
		return path, false, err
	}
	if err := hostsDir.Init(0755); err != nil {
		return path, false, err
	}

	data := MCPLocalhostConfig(adminAddr, allowed)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mcp.localhost-*.tmp")
	if err != nil {
		return path, false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return path, false, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return path, false, err
	}
	if err := tmp.Close(); err != nil {
		return path, false, err
	}
	if _, err := parser.ParseHostConfig(tmpName); err != nil {
		return path, false, fmt.Errorf("generated host is invalid: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return path, false, err
	}
	return path, true, nil
}

// MCPLocalhostManaged reports whether the generated host exists and carries
// the managed marker. User-created mcp.localhost files are never removed.
func MCPLocalhostManaged(hostsDir expect.Folder) (exists, managed bool, err error) {
	path := hostsDir.FilePath(def.MCPLocalhostHost + ".hcl")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}
	return true, strings.HasPrefix(string(data), MCPHostMarker), nil
}

// RemoveMCPLocalhost removes only the generated host.
func RemoveMCPLocalhost(hostsDir expect.Folder) (removed bool, err error) {
	exists, managed, err := MCPLocalhostManaged(hostsDir)
	if err != nil || !exists {
		return false, err
	}
	if !managed {
		return false, fmt.Errorf("mcp.localhost exists but is not managed by the MCP page")
	}
	return true, os.Remove(hostsDir.FilePath(def.MCPLocalhostHost + ".hcl"))
}
