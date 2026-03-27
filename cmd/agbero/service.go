package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"charm.land/huh/v2"
	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/kardianos/service"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll/lx"
)

type program struct {
	configPath    string
	devMode       bool
	shutdown      *jack.Shutdown
	server        *agbero.Server
	clusterStart  bool
	clusterJoinIP string
	clusterSecret string
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	p.shutdown.TriggerShutdown()
	return nil
}

func (p *program) run() {
	logger.Info("starting agbero proxy service")

	global, err := loadConfig(p.configPath)
	if err != nil {
		logger.Fields("file", p.configPath, "err", err).Fatal("failed to load config")
		return
	}

	if global.Security.Keeper.Enabled.Active() && global.Security.Keeper.Passphrase.Empty() && service.Interactive() {
		var pass string
		err := huh.NewInput().
			Title("Keeper Passphrase").
			Description("Unlock the encrypted secret store").
			EchoMode(huh.EchoModePassword).
			Value(&pass).
			Run()

		if err == nil && pass != "" {
			global.Security.Keeper.Passphrase = alaye.ValuePlain(pass)
		} else {
			logger.Fatal("Passphrase is required to start Agbero when Keeper is enabled.")
			return
		}
	}

	if p.clusterStart || p.clusterJoinIP != "" {
		global.Gossip.Enabled = alaye.Active
		if p.clusterJoinIP != "" {
			global.Gossip.Seeds = []string{p.clusterJoinIP}
		}
		if p.clusterSecret != "" {
			global.Gossip.SecretKey = alaye.Value(p.clusterSecret)
		}
	}

	if global.Storage.DataDir != "" {
		if err := os.MkdirAll(global.Storage.DataDir, woos.DirPerm); err == nil {
			pidFile := filepath.Join(global.Storage.DataDir, "agbero.pid")
			_ = os.WriteFile(pidFile, fmt.Appendf(nil, "%d", os.Getpid()), 0644)
			p.shutdown.RegisterFunc("PIDFile", func() { _ = os.Remove(pidFile) })
		}
	}

	if p.devMode {
		logger.Level(lx.LevelDebug)
		logger.Warn("running in development mode")
		global.Development = true
	}

	hostFolder := woos.MakeFolder(global.Storage.HostsDir, woos.HostDir)
	hm := discovery.NewHost(hostFolder, discovery.WithLogger(logger))

	p.shutdown.RegisterFunc("HostManager", func() {
		if err := hm.Close(); err != nil {
			logger.Error("host manager close error", err)
		}
	})

	if err := hm.Watch(); err != nil {
		logger.Fields("dir", hostFolder, "err", err).Fatal("failed to watch hosts")
		return
	}

	logger.Fields("os", runtime.GOOS, "euid", os.Geteuid()).Info("service starting")

	p.server = agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(logger),
		agbero.WithShutdownManager(p.shutdown),
	)

	go func() {
		if err := p.server.Start(p.configPath); err != nil {
			logger.Error(err)
			p.shutdown.TriggerShutdown()
		}
	}()

	hosts, _ := hm.LoadAll()
	logger.Fields("hosts_count", len(hosts)).Info("service running")

	stats := p.shutdown.Wait()
	logger.Fields(
		"duration", stats.EndTime.Sub(stats.StartTime),
		"tasks_total", stats.TotalEvents,
		"tasks_failed", stats.FailedEvents,
	).Info("agbero stopped gracefully")
}
