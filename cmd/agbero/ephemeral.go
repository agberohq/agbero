package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero"
	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
)

func runEphemeral(global *alaye.Global, hosts map[string]*alaye.Host) {
	l := ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout)),
		ll.WithFatalExits(true),
	).Enable()

	shutdown := jack.NewShutdown(
		jack.ShutdownWithTimeout(5*time.Second),
		jack.ShutdownWithSignals(os.Interrupt, syscall.SIGTERM),
	)

	// Initialize HostManager in static mode
	hm := discovery.NewHostFolder(woos.NewFolder(""), discovery.WithLogger(l))
	hm.LoadStatic(hosts)

	srv := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(l),
		agbero.WithShutdownManager(shutdown),
	)

	if err := srv.Start(""); err != nil {
		l.Fatal("server failed: ", err)
	}
}

func handleServe(path string, port int, bindHost string, useHTTPS bool) {
	if path == "" {
		path = "."
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		os.Exit(1)
	}

	stat, err := os.Stat(absPath)
	if err != nil || !stat.IsDir() {
		fmt.Printf("Path must be a valid directory: %s\n", absPath)
		os.Exit(1)
	}

	global := alaye.NewEphemeralGlobal(port, useHTTPS)
	if bindHost != "" {
		addr := fmt.Sprintf("%s:%d", bindHost, port)
		if useHTTPS {
			global.Bind.HTTPS = []string{addr}
		} else {
			global.Bind.HTTP = []string{addr}
		}
	}

	hostConfig := alaye.NewStaticHost("localhost", absPath, false)

	// If HTTPS is requested but user didn't specify a domain, localhost is assumed.
	// Agbero's TLS logic will handle localhost cert generation automatically.

	hosts := map[string]*alaye.Host{
		"localhost": hostConfig,
	}

	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}

	fmt.Printf("\nServing %s on %s://%s:%d\n\n", absPath, scheme, or(bindHost, "localhost"), port)
	runEphemeral(global, hosts)
}

func handleProxy(target string, port int, bindHost string, domain string, useHTTPS bool) {
	if target == "" {
		fmt.Println("Error: target required (e.g., :3000 or http://127.0.0.1:3000)")
		os.Exit(1)
	}

	if strings.HasPrefix(target, ":") {
		target = "127.0.0.1" + target
	}
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	if domain == "" {
		domain = "localhost"
	}

	global := alaye.NewEphemeralGlobal(port, useHTTPS)
	if bindHost != "" {
		addr := fmt.Sprintf("%s:%d", bindHost, port)
		if useHTTPS {
			global.Bind.HTTPS = []string{addr}
		} else {
			global.Bind.HTTP = []string{addr}
		}
	}

	hostConfig := alaye.NewStaticHost(domain, target, true)

	hosts := map[string]*alaye.Host{
		domain: hostConfig,
	}

	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}

	fmt.Printf("\nProxying %s -> %s\n", domain, target)
	fmt.Printf("Listening on %s://%s:%d\n\n", scheme, or(bindHost, "localhost"), port)
	runEphemeral(global, hosts)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
