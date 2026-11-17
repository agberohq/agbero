package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agberohq/agbero/cmd/agbero/helper"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
	agmcp "github.com/agberohq/agbero/internal/operation/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/olekukonko/ll"
)

// runMCPServe runs the read/plan MCP server over stdio. It is deliberately
// offline: config tools read the configuration tree, runtime tools return
// admin_plane_required. The daemon /mcp façade is the online path.
func runMCPServe(configPath string, logger *ll.Logger) {
	global, err := helper.LoadGlobal(configPath)
	if err != nil {
		logger.Fatal("load config: ", err)
	}
	if !global.MCP.Enabled.Active() {
		logger.Fatal("mcp.enabled is off; set it to \"on\" before running 'agbero mcp serve'")
	}

	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(logger))
	if _, err := hm.LoadCanonicalByDomain(); err != nil {
		logger.Fatal("load hosts: ", err)
	}

	allowed := make(map[string]bool)
	if global.MCP.Read.Enabled.Active() {
		for _, name := range global.MCP.Read.Allow {
			allowed[name] = true
		}
	}
	if global.MCP.Plan.Enabled.Active() {
		for _, name := range global.MCP.Plan.Allow {
			allowed[name] = true
		}
	}

	server := agmcp.NewServer(woos.Version,
		"Agbero MCP is read/plan only. This stdio server is offline; runtime tools require the daemon.")
	deps := agmcp.ReadDeps{
		Version:   woos.Version,
		Commit:    woos.Commit,
		BuildDate: woos.Date,
		StartedAt: time.Now(),
		Mode:      def.MCPModeOffline,
		Offline:   true,
		Global:    global,
		Hosts: func() (map[string]*alaye.Host, error) {
			return hm.LoadCanonicalByDomain()
		},
	}
	agmcp.RegisterReadTools(server, deps, allowed)
	agmcp.RegisterResources(server, deps, allowed)
	agmcp.RegisterPrompts(server)

	switch strings.ToLower(strings.TrimSpace(global.MCP.Transport)) {
	case def.MCPTransportUnix:
		runMCPUnix(server, global, logger)
	default:
		if err := agmcp.RunStdio(context.Background(), server); err != nil {
			logger.Fatal("mcp serve: ", err)
		}
	}
}

func runMCPUnix(server *sdk.Server, global *alaye.Global, logger *ll.Logger) {
	socket := strings.TrimSpace(global.MCP.Socket)
	if socket == "" {
		socket = global.Storage.DataDir.FilePath("mcp.sock")
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		logger.Fatal("create mcp socket dir: ", err)
	}
	_ = os.Remove(socket)
	ln, err := net.Listen(def.MCPTransportUnix, socket)
	if err != nil {
		logger.Fatal("listen mcp socket: ", err)
	}
	if err := os.Chmod(socket, 0660); err != nil {
		logger.Warn("chmod mcp socket: ", err)
	}
	logger.Info("mcp unix socket listening at ", socket)

	ctx := context.Background()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Fatal("accept mcp socket: ", err)
		}
		go func(conn net.Conn) {
			defer conn.Close()
			session, err := server.Connect(ctx, &sdk.IOTransport{Reader: conn, Writer: conn}, nil)
			if err != nil {
				return
			}
			_ = session.Wait()
		}(conn)
	}
}
