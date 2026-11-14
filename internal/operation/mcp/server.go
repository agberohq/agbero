package mcp

import (
	"context"
	"net/http"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// Protocol20260728 is the current stateless revision.
	Protocol20260728 = "2026-07-28"
	// Protocol20251125 and Protocol20250618 are the supported legacy
	// initialize-handshake revisions.
	Protocol20251125 = "2025-11-25"
	Protocol20250618 = "2025-06-18"
)

// SupportedProtocolVersions is the set Agbero advertises.
var SupportedProtocolVersions = []string{
	Protocol20260728,
	Protocol20251125,
	Protocol20250618,
}

// NewServer builds the SDK server with Agbero's identity and protocol set.
// Tools are registered by the caller.
func NewServer(version, instructions string) *sdk.Server {
	return sdk.NewServer(
		&sdk.Implementation{Name: "agbero", Version: version},
		&sdk.ServerOptions{
			Instructions:              instructions,
			SupportedProtocolVersions: SupportedProtocolVersions,
		},
	)
}

// RunStdio runs the server over stdin/stdout until the client disconnects.
func RunStdio(ctx context.Context, server *sdk.Server) error {
	return server.Run(ctx, &sdk.StdioTransport{})
}

// StreamableHandler returns the loopback HTTP handler. 2026-07-28 is stateless
// by specification. The daemon wraps it with mcp.allowed_ips and the
// bearer-token middleware before mounting.
func StreamableHandler(server *sdk.Server) http.Handler {
	return sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true},
	)
}
