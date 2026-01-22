package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"git.imaxinacion.net/aibox/agbero/internal/config"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/proxy"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
	"github.com/urfave/cli/v2"
)

var (
	logger = ll.New(config.Name).Enable()
)

func main() {
	// Setup logging

	app := &cli.App{
		Name:    config.Name,
		Version: config.Version,
		Usage:   config.Description,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "/etc/agbero/config.hcl",
				Usage:   "Path to global config",
			},
			&cli.BoolFlag{
				Name:  "dev",
				Usage: "Development mode",
				Value: false,
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "start",
				Usage:  "Start the proxy server",
				Action: startProxy,
			},
			{
				Name:   "validate",
				Usage:  "Validate configuration",
				Action: validateConfig,
			},
			{
				Name:   "hosts",
				Usage:  "List configured hosts",
				Action: listHosts,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatal("failed to run")
		os.Exit(1)
	}
}

func startProxy(c *cli.Context) error {
	logger.Info("starting agbero proxy")

	var global *config.GlobalConfig
	p := config.NewParser(c.String("config"))
	err := p.Unmarshal(&global)
	if err != nil {
		return err
	}
	if c.Bool("dev") {
		logger.Level(lx.LevelDebug)
		logger.Warn("running in development mode")
	}

	// Initialize host discovery
	hm := discovery.NewHost(global.HostsDir)
	if err := hm.Watch(); err != nil {
		return err
	}

	// Create and start proxy server
	server := proxy.NewServer(proxy.WithHostManager(hm), proxy.WithGlobalConfig(global))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		ll.Info("shutting down gracefully")
		cancel()
	}()

	return server.Start(ctx)
}

func validateConfig(c *cli.Context) error {

	var global *config.GlobalConfig
	p := config.NewParser(c.String("config"))
	err := p.Unmarshal(&global)
	if err != nil {
		return err
	}

	// Validate all host configs
	hm := discovery.NewHost(global.HostsDir)
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	ll.Fields("hosts", len(hosts)).Info("configuration valid")
	return nil
}

func listHosts(c *cli.Context) error {

	var host *config.GlobalConfig
	p := config.NewParser(c.String("config"))
	err := p.Unmarshal(&host)

	hm := discovery.NewHost(host.HostsDir)
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	for name, c := range hosts {
		logger.Fields(
			"host", name,
			"domains", c.Domains,
			"routes", len(c.Routes),
			"configured host")
	}

	return nil
}
