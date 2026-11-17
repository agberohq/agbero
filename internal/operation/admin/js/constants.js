// Shared admin UI constants. Keep protocol/scope literals out of page code.
export const ROUTE_PROTOCOLS = Object.freeze({
    HTTP: 'http',
    MCP:  'mcp',
});

export const MCP_SCOPES = Object.freeze({
    READ: 'mcp:read',
    PLAN: 'mcp:plan',
});

export const MCP_TRANSPORTS = Object.freeze({
    STDIO: 'stdio',
    UNIX:  'unix',
});
