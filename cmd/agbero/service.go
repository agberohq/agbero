package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"git.imaxinacion.net/aibox/agbero"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/kardianos/service"
	"github.com/olekukonko/ll/lx"
)

type program struct {
	configPath string
	devMode    bool
	ctx        context.Context
	cancel     context.CancelFunc
	exit       chan struct{}
}

func (p *program) Start(s service.Service) error {
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	<-p.exit
	return nil
}

func (p *program) run() {
	defer close(p.exit)
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

	// Use woos.MakeFolder and NewHostFolder
	hostFolder := woos.MakeFolder(global.Storage.HostsDir, woos.HostDir)

	hm := discovery.NewHostFolder(hostFolder, discovery.WithLogger(logger))
	if err := hm.Watch(); err != nil {
		logger.Fields("dir", hostFolder, "err", err).Fatal("failed to watch hosts")
		return
	}
	defer hm.Close()

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

	server := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(logger),
	)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	runCtx, runCancel := context.WithCancel(p.ctx)

	go func() {
		select {
		case <-p.ctx.Done():
		case <-sigChan:
			logger.Info("shutting down via signal")
			runCancel()
		}
	}()

	// Pass configPath for reload capability
	if err := server.Start(runCtx, p.configPath); err != nil {
		logger.Error(err)
	}

	hosts, _ := hm.LoadAll()
	logger.Fields("hosts_count", len(hosts)).Info("service running")
}
