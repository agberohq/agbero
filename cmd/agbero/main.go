package main

import (
	"log"
	"os"
	"runtime"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
)

var (
	logger  *ll.Logger
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

	cmdHelp := flaggy.NewSubcommand("help")
	cmdHelp.Description = "Show help and usage examples"

	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdStart, 1)
	flaggy.AttachSubcommand(cmdStop, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdValidate, 1)
	flaggy.AttachSubcommand(cmdHosts, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)

	flaggy.Parse()
	welcome()

	// Handle help command early
	if cmdHelp.Used {
		showHelpExamples(configPath)
		return
	}

	fp, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer fp.Close()

	// Setup logging
	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(true))
	loggerFile := lh.NewJSONHandler(fp)
	loggerMultiple := lh.NewMultiHandler(loggerTerminal, loggerFile)

	logger = ll.New(woos.Name, ll.WithHandler(loggerMultiple)).Enable()

	// Apply defaults if flag not set
	if configPath == "" {
		configPath = defaultConfig
	}

	// 3. Setup Service Config
	svcConfig := &service.Config{
		Name:        "agbero",
		DisplayName: "Agbero Proxy",
		Description: "High-performance reverse proxy with Let's Encrypt support",
		Arguments:   []string{"run", "-c", configPath},
	}

	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	// Add platform-specific configuration for macOS
	if runtime.GOOS == "darwin" {
		if os.Geteuid() == 0 {
			// Running as root - configure as system LaunchDaemon
			svcConfig.Option = service.KeyValue{
				"RunAtLoad":   true,
				"KeepAlive":   true,
				"SessionType": "System",
			}
		} else {
			// Running as user - configure as LaunchAgent
			svcConfig.Name = "net.imaxinacion.agbero"
			svcConfig.Option = service.KeyValue{
				"RunAtLoad":     true,
				"KeepAlive":     true,
				"SessionCreate": true,
			}
		}
	}

	prg := &program{
		configPath: configPath,
		devMode:    devMode,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Fatal("Failed to create service: ", err)
	}

	// 4. Handle Service Management Commands
	if cmdInstall.Used {
		logger.Info("Installing service...")
		if err := installDefaults(); err != nil {
			logger.Fatal("Failed to setup defaults: ", err)
		}
		if err := s.Install(); err != nil {
			enhancedErr := handleServiceError(err, "install", configPath)
			logger.Fatal("Failed to install service: ", enhancedErr)
		}

		logger.Info("Service installed successfully")

		// Give helpful post-install instructions
		if runtime.GOOS == "darwin" {
			if os.Geteuid() == 0 {
				logger.Info("System LaunchDaemon installed at: /Library/LaunchDaemons/agbero.plist")
				logger.Info("To start: sudo launchctl load /Library/LaunchDaemons/agbero.plist")
				logger.Info("To check: sudo launchctl list | grep agbero")
				logger.Info("To stop:  sudo launchctl unload /Library/LaunchDaemons/agbero.plist")
			} else {
				logger.Info("User LaunchAgent installed at: ~/Library/LaunchAgents/net.imaxinacion.agbero.plist")
				logger.Info("To start: launchctl load ~/Library/LaunchAgents/net.imaxinacion.agbero.plist")
				logger.Info("To check: launchctl list | grep agbero")
				logger.Info("To stop:  launchctl unload ~/Library/LaunchAgents/net.imaxinacion.agbero.plist")
			}
		} else if runtime.GOOS == "linux" {
			logger.Info("Systemd service installed")
			logger.Info("To start: sudo systemctl start agbero")
			logger.Info("To enable at boot: sudo systemctl enable agbero")
			logger.Info("To check: sudo systemctl status agbero")
		} else if runtime.GOOS == "windows" {
			logger.Info("Windows Service installed")
			logger.Info("To manage: Open Services (services.msc)")
			logger.Info("Or use: sc query agbero")
		}
		return
	}

	if cmdStart.Used {
		logger.Info("Starting service...")
		if err := s.Start(); err != nil {
			enhancedErr := handleServiceError(err, "start", configPath)
			logger.Fatal("Failed to start service: ", enhancedErr)
		}
		logger.Info("Service started")
		return
	}

	if cmdStop.Used {
		logger.Info("Stopping service...")
		if err := s.Stop(); err != nil {
			enhancedErr := handleServiceError(err, "stop", configPath)
			logger.Fatal("Failed to stop service: ", enhancedErr)
		}
		logger.Info("Service stopped")
		return
	}

	if cmdUninstall.Used {
		logger.Info("Uninstalling service...")
		if err := s.Uninstall(); err != nil {
			enhancedErr := handleServiceError(err, "uninstall", configPath)
			logger.Fatal("Failed to uninstall service: ", enhancedErr)
		}
		logger.Info("Service uninstalled")
		return
	}

	// 5. Handle Utility Commands
	if cmdValidate.Used {
		logger.Info("Validating configuration...")
		if err := validateConfig(configPath); err != nil {
			logger.Fatal("Configuration validation failed: ", err)
		}
		return
	}

	if cmdHosts.Used {
		logger.Info("Listing configured hosts...")
		if err := listHosts(configPath); err != nil {
			logger.Fatal("Failed to list hosts: ", err)
		}
		return
	}

	// 6. Default Action: Run (Interactive or Service)
	if cmdRun.Used {
		// We are running in the terminal
		logger.Info("Running in interactive mode. Press Ctrl+C to stop.")
		if devMode {
			logger.Warn("Development mode enabled")
		}

		// Setup system logger for the service wrapper
		errs := make(chan error, 5)

		// Only attach system logger if NOT running interactively
		if !service.Interactive() {
			sysLogger, err := s.Logger(errs)
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				for {
					err := <-errs
					if err != nil {
						log.Printf("Service error: %v", err)
					}
				}
			}()
			_ = sysLogger // Keep reference
		}

		// s.Run() is smart:
		// - If called from terminal, it runs foreground.
		// - If called by launchd/systemd, it hooks into the service system.
		if err := s.Run(); err != nil {
			logger.Error("Service exited with error: ", err)
			os.Exit(1)
		}
		return
	}

	// 7. No command specified, show help
	showHelpExamples(configPath)
}
