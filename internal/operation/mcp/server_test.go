package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestSupportedProtocolVersions(t *testing.T) {
	want := map[string]bool{
		Protocol20260728: false,
		Protocol20251125: false,
		Protocol20250618: false,
	}
	for _, v := range SupportedProtocolVersions {
		if _, ok := want[v]; !ok {
			t.Fatalf("unexpected protocol version %q", v)
		}
		want[v] = true
	}
	for v, seen := range want {
		if !seen {
			t.Fatalf("missing protocol version %q", v)
		}
	}
	if len(SupportedProtocolVersions) != 3 {
		t.Fatalf("supported versions = %v; want exactly 3", SupportedProtocolVersions)
	}
}

// Negotiates the current stateless revision before any tool code is involved.
func TestServerNegotiatesCurrentProtocol(t *testing.T) {
	ctx := context.Background()
	server := NewServer("test", "read/plan only")
	serverTransport, clientTransport := sdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer clientSession.Close()

	init := clientSession.InitializeResult()
	if init == nil {
		t.Fatal("no initialize result")
	}
	if init.ProtocolVersion != Protocol20260728 {
		t.Fatalf("negotiated protocol = %q, want %q", init.ProtocolVersion, Protocol20260728)
	}
	if init.ServerInfo == nil || init.ServerInfo.Name != "agbero" {
		t.Fatalf("server info = %+v", init.ServerInfo)
	}
}

func TestStreamableHandler(t *testing.T) {
	if h := StreamableHandler(NewServer("test", "")); h == nil {
		t.Fatal("nil streamable handler")
	}
}

func TestStreamableHandlerServesLegacyInitialize(t *testing.T) {
	srv := httptest.NewServer(StreamableHandler(NewServer("test", "")))
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", res.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "2025-11-25") {
		t.Fatalf("initialize response did not negotiate 2025-11-25: %s", raw)
	}
}

func TestConfigToolAndResourcesOverSDK(t *testing.T) {
	ctx := context.Background()
	server := NewServer("test", "")
	deps := ReadDeps{Offline: true, Mode: def.MCPModeOffline, Global: &alaye.Global{}}
	allowed := map[string]bool{"config.global": true, "status": true, "config.plan": true}
	RegisterReadTools(server, deps, allowed)
	RegisterResources(server, deps, allowed)
	RegisterPrompts(server)

	st, ct := sdk.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "agbero_config_get_global"})
	if err != nil {
		t.Fatalf("tool call: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %+v", res.Content)
	}

	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources.Resources) == 0 {
		t.Fatal("no resources registered")
	}
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(prompts.Prompts) == 0 {
		t.Fatal("no prompts registered")
	}
}
