package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/security"
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

	// Key Management Flags
	keyService string
	keyTTL     time.Duration
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
	flaggy.SetVersion(version) // Handles --version automatically

	// Global flags
	flaggy.String(&configPath, "c", "config", "Path to configuration file (default: "+defaultConfig+")")
	flaggy.Bool(&devMode, "d", "dev", "Enable development mode")

	// --- Service Subcommands ---
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

	// --- Key Management Subcommands ---
	cmdKey := flaggy.NewSubcommand("key")
	cmdKey.Description = "Manage identity keys for gossip authentication"

	cmdKeyGen := flaggy.NewSubcommand("gen")
	cmdKeyGen.Description = "Generate a signed identity token for a service"
	cmdKeyGen.String(&keyService, "s", "service", "Service name (e.g. 'dance-app') (required)")
	cmdKeyGen.Duration(&keyTTL, "t", "ttl", "Token validity duration (default: 8760h / 1 year)")

	cmdKeyInit := flaggy.NewSubcommand("init")
	cmdKeyInit.Description = "Generate the server Ed25519 Private Key file"

	// Attach Subcommands
	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdStart, 1)
	flaggy.AttachSubcommand(cmdStop, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdValidate, 1)
	flaggy.AttachSubcommand(cmdHosts, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)

	cmdKey.AttachSubcommand(cmdKeyGen, 1)
	cmdKey.AttachSubcommand(cmdKeyInit, 1)
	flaggy.AttachSubcommand(cmdKey, 1)

	flaggy.Parse()
	welcome()

	// Apply defaults if flag not set
	if configPath == "" {
		configPath = defaultConfig
	}

	// Handle Help
	if cmdHelp.Used {
		showHelpExamples(configPath)
		return
	}

	// --- Handle Key Commands (Exit early) ---
	if cmdKey.Used {
		if cmdKeyInit.Used {
			target := "server.key"
			// Try to find path from config, ignore errors if config is missing
			if global, err := loadConfig(configPath); err == nil && &global.Gossip != nil && global.Gossip.PrivateKeyFile != "" {
				target = global.Gossip.PrivateKeyFile
			}

			if err := security.GenerateNewKeyFile(target); err != nil {
				fmt.Printf("Error generating key: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Generated private key: %s\n", target)
			fmt.Println("Ensure your config.hcl has: gossip { private_key_file = \"" + target + "\" }")
			return
		}

		if cmdKeyGen.Used {
			if keyService == "" {
				fmt.Println("Error: --service name is required")
				os.Exit(1)
			}
			if keyTTL == 0 {
				keyTTL = 24 * 365 * time.Hour
			}

			global, err := loadConfig(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}

			if &global.Gossip == nil || global.Gossip.PrivateKeyFile == "" {
				fmt.Println("Error: 'gossip.private_key_file' is not set in config.hcl")
				os.Exit(1)
			}

			tm, err := security.LoadKeys(global.Gossip.PrivateKeyFile)
			if err != nil {
				fmt.Printf("Error loading private key: %v\n", err)
				os.Exit(1)
			}

			token, err := tm.Mint(keyService, keyTTL)
			if err != nil {
				fmt.Printf("Error minting token: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(token)
			return
		}

		flaggy.ShowHelpAndExit("key")
		return
	}

	// --- Setup TlsLogger ---
	fp, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer fp.Close()

	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(true))
	loggerFile := lh.NewJSONHandler(fp)
	loggerMultiple := lh.NewMultiHandler(loggerTerminal, loggerFile)

	logger = ll.New(woos.Name,
		ll.WithHandler(loggerMultiple),
		ll.WithFatalExits(true),
	).Enable()

	// --- Setup Service ---
	svcConfig := &service.Config{
		Name:        "agbero",
		DisplayName: "Agbero Proxy",
		Description: "High-performance reverse proxy with Let's Encrypt support",
		Arguments:   []string{"run", "-c", configPath},
	}

	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	if runtime.GOOS == "darwin" {
		if os.Geteuid() == 0 {
			svcConfig.Option = service.KeyValue{
				"RunAtLoad":   true,
				"KeepAlive":   true,
				"SessionType": "System",
			}
		} else {
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

	// --- Handle Service Commands ---
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

		if runtime.GOOS == "darwin" {
			if os.Geteuid() == 0 {
				logger.Info("System LaunchDaemon installed at: /Library/LaunchDaemons/agbero.plist")
				logger.Info("To start: sudo launchctl load /Library/LaunchDaemons/agbero.plist")
			} else {
				logger.Info("User LaunchAgent installed at: ~/Library/LaunchAgents/net.imaxinacion.agbero.plist")
				logger.Info("To start: launchctl load ~/Library/LaunchAgents/net.imaxinacion.agbero.plist")
			}
		} else if runtime.GOOS == "linux" {
			logger.Info("Systemd service installed")
			logger.Info("To start: sudo systemctl start agbero")
		} else if runtime.GOOS == "windows" {
			logger.Info("Windows Service installed")
			logger.Info("To start: net start agbero")
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

	// --- Handle Utility Commands ---
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

	// --- Run Command ---
	if cmdRun.Used {
		logger.Info("Running in interactive mode. Press Ctrl+C to stop.")
		if devMode {
			logger.Warn("Development mode enabled")
		}

		errs := make(chan error, 5)

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
			_ = sysLogger
		}

		if err := s.Run(); err != nil {
			logger.Error("Service exited with error: ", err)
			os.Exit(1)
		}
		return
	}

	// Default: Show usage
	showHelpExamples(configPath)
}
