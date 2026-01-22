package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"git.imaxinacion.net/aibox/agbero"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lx"
	"github.com/urfave/cli/v2"
)

var (
	logger = ll.New(woos.Name).Enable()
)

func main() {
	app := &cli.App{
		Name:    woos.Name,
		Version: woos.Version,
		Usage:   woos.Description,
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
		logger.Fatal(err)
		os.Exit(1)
	}
}

func startProxy(c *cli.Context) error {
	logger.Info("starting agbero proxy")

	// FIX 1: Use a struct instance, not a nil pointer
	var global woos.GlobalConfig
	p := woos.NewParser(c.String("config"))

	// FIX 2: Check error immediately
	if err := p.Unmarshal(&global); err != nil {
		return err
	}

	if c.Bool("dev") {
		logger.Level(lx.LevelDebug)
		logger.Warn("running in development mode")
		global.Development = true
	}

	hm := discovery.NewHost(global.HostsDir)
	if err := hm.Watch(); err != nil {
		return err
	}
	defer hm.Close() // Good practice to close watcher

	server := agbero.NewServer(agbero.WithHostManager(hm), agbero.WithGlobalConfig(&global))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
	// FIX 1: Use struct instance
	var global woos.GlobalConfig
	p := woos.NewParser(c.String("config"))

	// FIX 2: Check error
	if err := p.Unmarshal(&global); err != nil {
		return err
	}

	hm := discovery.NewHost(global.HostsDir)
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	ll.Fields("hosts", len(hosts)).Info("configuration valid")
	return nil
}

func listHosts(c *cli.Context) error {
	// FIX: Do not use a pointer here directly.
	// var host *config.GlobalConfig <-- WRONG (nil pointer)

	var host woos.GlobalConfig // CORRECT (struct instance)

	p := woos.NewParser(c.String("config"))
	err := p.Unmarshal(&host) // Pass address of struct
	if err != nil {
		return err
	}

	hm := discovery.NewHost(host.HostsDir)
	// ... rest of function
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	for name, c := range hosts {
		logger.Fields(
			"host", name,
			"domains", c.Domains,
			"routes", len(c.Routes),
			"configured host").Info("host found") // Fixed logger call structure
	}

	return nil
}
