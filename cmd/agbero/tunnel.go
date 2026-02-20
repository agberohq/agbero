package main

import (
	"fmt"
	"os"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/tunnel"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
)

var (
	tunnelServer        string
	tunnelUser          string
	tunnelKey           string
	tunnelPassword      bool
	tunnelLocalPort     string
	tunnelRemoteHost    string
	tunnelRemotePort    string
	tunnelAutoReconnect bool
)

func handleTunnel() {
	if tunnelServer == "" {
		fmt.Println("Error: --server is required (e.g., example.com)")
		os.Exit(1)
	}

	if tunnelRemoteHost == "" || tunnelRemotePort == "" {
		fmt.Println("Error: --remote-host and --remote-port are required")
		os.Exit(1)
	}

	if tunnelUser == "" {
		tunnelUser = tunnel.DefaultSSHUser
	}
	if tunnelLocalPort == "" {
		tunnelLocalPort = tunnel.DefaultTunnelPort
	}

	cfg := tunnel.Config{
		Server:        tunnelServer,
		User:          tunnelUser,
		KeyPath:       tunnelKey,
		UsePassword:   tunnelPassword,
		LocalHost:     "127.0.0.1",
		LocalPort:     tunnelLocalPort,
		RemoteHost:    tunnelRemoteHost,
		RemotePort:    tunnelRemotePort,
		AutoReconnect: tunnelAutoReconnect,
		MaxRetries:    10,
		RetryDelay:    5 * time.Second,
	}

	l := ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout)),
		ll.WithFatalExits(true),
	).Enable()

	t, err := tunnel.New(l, cfg)
	if err != nil {
		l.Fatal("Failed to initialize tunnel: ", err)
	}

	if err := t.Start(); err != nil {
		l.Fatal("Tunnel stopped with error: ", err)
	}
}
