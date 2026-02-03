package main

import (
	"os"
	"runtime"

	"git.imaxinacion.net/aibox/agbero"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/kardianos/service"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll/lx"
)

type program struct {
	configPath string
	devMode    bool
	shutdown   *jack.Shutdown // Use the passed-in instance
}

func (p *program) Start(s service.Service) error {
	// We do NOT create a new shutdown instance here. We use p.shutdown.
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	// Trigger the Jack shutdown, which will unblock p.shutdown.Wait() in run()
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

	if p.devMode {
		logger.Level(lx.LevelDebug)
		logger.Warn("running in development mode")
		global.Development = true
	}

	hostFolder := woos.MakeFolder(global.Storage.HostsDir, woos.HostDir)

	hm := discovery.NewHostFolder(hostFolder, discovery.WithLogger(logger))

	// Register HostManager cleanup with Jack
	p.shutdown.RegisterFunc("HostManager", func() {
		if err := hm.Close(); err != nil {
			logger.Error("host manager close error", err)
		}
	})

	if err := hm.Watch(); err != nil {
		logger.Fields("dir", hostFolder, "err", err).Fatal("failed to watch hosts")
		return
	}

	logger.Fields(
		"os", runtime.GOOS,
		"euid", os.Geteuid(),
		"config", p.configPath,
	).Info("service starting")

	logger.Fields(
		"hosts_dir", global.Storage.HostsDir,
		"certs_dir", global.Storage.CertsDir,
		"https", len(global.Bind.HTTPS),
	).Info("resolved paths")

	// Pass Shutdown manager to Server via new Option
	server := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(logger),
		agbero.WithShutdownManager(p.shutdown),
	)

	// Start server in goroutine; Start() blocks until shutdown triggers
	go func() {
		if err := server.Start(p.configPath); err != nil {
			logger.Error(err)
			// If server fails to start, trigger shutdown to exit program
			p.shutdown.TriggerShutdown()
		}
	}()

	hosts, _ := hm.LoadAll()
	logger.Fields("hosts_count", len(hosts)).Info("service running")

	// Block here until Stop() is called or OS signal received
	stats := p.shutdown.Wait()

	logger.Fields(
		"duration", stats.EndTime.Sub(stats.StartTime),
		"tasks_total", stats.TotalEvents,
		"tasks_failed", stats.FailedEvents,
	).Info("agbero stopped gracefully")
}
