package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type ephemeral struct {
	logger   *ll.Logger
	shutdown *jack.Shutdown
	path     string
	target   string
	bindHost string
	port     int
	domain   string
	useHTTPS bool
}

func runEphemeral(e *ephemeral, global *alaye.Global, hosts map[string]*alaye.Host) {
	hm := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(e.logger))
	hm.LoadStatic(hosts)

	l, _ := zulu.Logging(&global.Logging, devMode, e.shutdown)

	srv := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(l),
		agbero.WithShutdownManager(e.shutdown),
	)

	go func() {
		if err := srv.Start(""); err != nil {
			logger.Error(err)
			e.shutdown.TriggerShutdown()
		}
	}()

	stats := e.shutdown.Wait()

	logger.Fields(
		"duration", stats.EndTime.Sub(stats.StartTime),
		"tasks_total", stats.TotalEvents,
		"tasks_failed", stats.FailedEvents,
	).Info("agbero stopped gracefully")
}

func (e *ephemeral) createGlobal(port int, ctx *installer.Context) *alaye.Global {
	global := alaye.NewEphemeralGlobal(port, e.useHTTPS)

	if e.bindHost != "" {
		addr := fmt.Sprintf("%s:%d", e.bindHost, port)
		if e.useHTTPS {
			global.Bind.HTTPS = []string{addr}
		} else {
			global.Bind.HTTP = []string{addr}
		}
	}

	if ctx != nil {
		global.Storage.CertsDir = ctx.Paths.CertsDir.Path()
		global.Storage.DataDir = ctx.Paths.DataDir.Path()
		global.Storage.WorkDir = ctx.Paths.WorkDir.Path()
	}

	return global
}

func (e *ephemeral) getScheme() string {
	if e.useHTTPS {
		return "https"
	}
	return "http"
}

func (e *ephemeral) handleServe() {
	e.path = zulu.Or(e.path, ".")

	absPath, err := filepath.Abs(e.path)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		os.Exit(1)
	}

	stat, err := os.Stat(absPath)
	if err != nil || !stat.IsDir() {
		fmt.Printf("Path must be a valid directory: %s\n", absPath)
		os.Exit(1)
	}

	finalPort, err := zulu.PortScan(e.bindHost, e.port, woos.MaxPortRetries)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	ctx := installer.NewContext(e.logger, "local")
	if e.useHTTPS {
		ca := installer.NewCA(ctx)
		if err := ca.PromptAndInstall(); err != nil {
			e.logger.Warn("CA installation prompt interrupted: ", err)
		}
		logger.Println()
	}

	global := e.createGlobal(finalPort, ctx)
	hostConfig := alaye.NewStaticHost("localhost", absPath, false)

	hosts := map[string]*alaye.Host{
		"localhost": hostConfig,
	}
	scheme := e.getScheme()
	host := fmt.Sprintf("%s://%s:%d", scheme, zulu.Or(e.bindHost, "localhost"), finalPort)

	logger.Fields("path", absPath).Infof("Serving Web Server")
	logger.Infof("web → %s", host)
	logger.Line(2)
	runEphemeral(e, global, hosts)
}

func (e *ephemeral) handleProxy() {
	if e.target == "" {
		fmt.Println("Error: target required (e.g., :3000 or http://127.0.0.1:3000)")
		os.Exit(1)
	}

	if strings.HasPrefix(e.target, ":") {
		e.target = "127.0.0.1" + e.target
	}
	if !strings.HasPrefix(e.target, "http") {
		e.target = "http://" + e.target
	}

	if e.domain == "" {
		e.domain = "localhost"
	}

	finalPort, err := zulu.PortScan(e.bindHost, e.port, woos.MaxPortRetries)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	ctx := installer.NewContext(e.logger, "local")
	if e.useHTTPS {
		ca := installer.NewCA(ctx)
		if err := ca.PromptAndInstall(); err != nil {
			e.logger.Warn("CA installation prompt interrupted: ", err)
		}
	}

	global := e.createGlobal(finalPort, ctx)
	hostConfig := alaye.NewStaticHost(e.domain, e.target, true)

	hosts := map[string]*alaye.Host{
		e.domain: hostConfig,
	}

	scheme := e.getScheme()
	logger.Infof("Proxying %s → %s\n", e.domain, e.target)
	logger.Infof("Listening on %s://%s:%d", scheme, zulu.Or(e.bindHost, "localhost"), finalPort)
	logger.Line(2)
	runEphemeral(e, global, hosts)
}
