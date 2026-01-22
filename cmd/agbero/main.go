package main

import (
	"log"
	"os"
	"runtime"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/ll"
)

var (
	logger  = ll.New(woos.Name).Enable()
	version = woos.Version
)

// CLI flags
var (
	configPath string
	devMode    bool
)

func main() {
	// 1. Default Configuration
	defaultConfig := "/etc/agbero/config.hcl"
	if runtime.GOOS == "windows" {
		defaultConfig = `C:\ProgramData\agbero\config.hcl`
	}

	// 2. Setup Flaggy
	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(version)

	// Global flags
	flaggy.String(&configPath, "c", "config", "Path to configuration file (default: "+defaultConfig+")")
	flaggy.Bool(&devMode, "d", "dev", "Enable development mode")

	// Subcommands
	cmdInstall := flaggy.NewSubcommand("install")
	cmdInstall.Description = "Install configuration files and system service"

	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdUninstall.Description = "Uninstall system service"

	cmdStart := flaggy.NewSubcommand("start")
	cmdStart.Description = "Start the system service"

	cmdStop := flaggy.NewSubcommand("stop")
	cmdStop.Description = "Stop the system service"

	cmdRun := flaggy.NewSubcommand("run")
	cmdRun.Description = "Run the proxy directly (interactive mode)"

	cmdValidate := flaggy.NewSubcommand("validate")
	cmdValidate.Description = "Validate configuration file"

	cmdHosts := flaggy.NewSubcommand("hosts")
	cmdHosts.Description = "List configured hosts"

	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdStart, 1)
	flaggy.AttachSubcommand(cmdStop, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdValidate, 1)
	flaggy.AttachSubcommand(cmdHosts, 1)

	flaggy.Parse()

	// Apply defaults if flag not set
	if configPath == "" {
		configPath = defaultConfig
	}

	// 3. Setup Service Config
	svcConfig := &service.Config{
		Name:        "agbero",
		DisplayName: "Agbero Proxy",
		Description: "High-performance reverse proxy with Let's Encrypt support",
		// Arguments passed to the binary when run by the service manager
		Arguments: []string{"run", "-c", configPath},
	}

	// If dev mode is on, pass that to the service arguments too
	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	prg := &program{
		configPath: configPath,
		devMode:    devMode,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Fatal(err)
	}

	// 4. Handle Subcommands
	if cmdInstall.Used {
		// Create default files before installing service
		if err := installDefaults(); err != nil {
			logger.Fatal("Failed to setup defaults: ", err)
		}
		if err := s.Install(); err != nil {
			logger.Fatal("Failed to install service: ", err)
		}
		logger.Info("Service installed successfully")
		return
	}

	if cmdUninstall.Used {
		if err := s.Uninstall(); err != nil {
			logger.Fatal("Failed to uninstall service: ", err)
		}
		logger.Info("Service uninstalled")
		return
	}

	if cmdStart.Used {
		if err := s.Start(); err != nil {
			logger.Fatal("Failed to start service: ", err)
		}
		logger.Info("Service started")
		return
	}

	if cmdStop.Used {
		if err := s.Stop(); err != nil {
			logger.Fatal("Failed to stop service: ", err)
		}
		logger.Info("Service stopped")
		return
	}

	if cmdValidate.Used {
		if err := validateConfig(configPath); err != nil {
			logger.Fatal(err)
		}
		return
	}

	if cmdHosts.Used {
		if err := listHosts(configPath); err != nil {
			logger.Fatal(err)
		}
		return
	}

	// Default Action: Run (either via "run" subcommand or if invoked by service manager)
	// If no subcommand is used, and it's not a service control command, we assume "run".

	// Setup system logger for the service wrapper
	errs := make(chan error, 5)
	logger, err := s.Logger(errs)
	if err != nil {
		log.Fatal(err)
	}

	// Forward service errors to log
	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Printf("Service error: %v", err)
			}
		}
	}()

	if err := s.Run(); err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}
