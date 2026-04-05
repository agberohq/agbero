package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/discovery"
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

	if p.clusterStart || p.clusterJoinIP != "" {
		global.Gossip.Enabled = alaye.Active
		if p.clusterJoinIP != "" {
			global.Gossip.Seeds = []string{p.clusterJoinIP}
		}
		if p.clusterSecret != "" {
			global.Gossip.SecretKey = expect.Value(p.clusterSecret)
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
