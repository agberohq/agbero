package def

// Route and MCP runtime identifiers. Keep these centralized so route
// validation, defaults, uptime, admin status, and CLI output cannot drift.
const (
	RouteProtocolHTTP = "http"
	RouteProtocolMCP  = "mcp"

	MCPSessionHeader = "Mcp-Session-Id"
	MCPSessionKey    = "header:" + MCPSessionHeader

	MCPModeDaemon  = "daemon"
	MCPModeOffline = "offline"

	MCPTransportStdio = "stdio"
	MCPTransportUnix  = "unix"

	MCPServiceName = "mcp"

	MCPLocalhostHost = "mcp.localhost"
	MCPLocalhostURL  = "https://" + MCPLocalhostHost
)
