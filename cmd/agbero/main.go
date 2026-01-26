package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/logging"
	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/charmbracelet/huh"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

var (
	// The single global logger instance
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

	// Certificate Management Flags
	forceCAInstall bool
	caMethod       string
	certDir        string

	// Gossip flags
	gossipService string
	gossipTTL     time.Duration
	enableGossip  bool
)

func main() {
	// 1) BOOTSTRAP LOGGER
	logger = ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(true))),
		ll.WithFatalExits(true),
	).Enable()

	// 2) Setup Flaggy
	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(version)

	// Global flags
	flaggy.String(&configPath, "c", "config", "Path to configuration file")
	flaggy.Bool(&devMode, "d", "dev", "Enable development mode")
	flaggy.Bool(&enableGossip, "", "gossip", "Enable/disable gossip in run mode")

	// --- Subcommands Setup ---
	cmdInstall := flaggy.NewSubcommand("install")
	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdStart := flaggy.NewSubcommand("start")
	cmdStop := flaggy.NewSubcommand("stop")
	cmdRun := flaggy.NewSubcommand("run")
	cmdValidate := flaggy.NewSubcommand("validate")
	cmdHosts := flaggy.NewSubcommand("hosts")
	cmdHelp := flaggy.NewSubcommand("help")

	// Certificate commands
	cmdCert := flaggy.NewSubcommand("cert")
	cmdInstallCA := flaggy.NewSubcommand("install-ca")
	cmdInstallCA.Bool(&forceCAInstall, "f", "force", "Force reinstall")
	cmdInstallCA.String(&caMethod, "m", "method", "Method: auto|mkcert|truststore")

	cmdListCerts := flaggy.NewSubcommand("list")
	cmdCertInfo := flaggy.NewSubcommand("info")
	cmdCertInfo.String(&certDir, "d", "dir", "Cert directory")

	cmdCert.AttachSubcommand(cmdInstallCA, 1)
	cmdCert.AttachSubcommand(cmdListCerts, 1)
	cmdCert.AttachSubcommand(cmdCertInfo, 1)

	// Key commands
	cmdKey := flaggy.NewSubcommand("key")
	cmdKeyGen := flaggy.NewSubcommand("gen")
	cmdKeyGen.String(&keyService, "s", "service", "Service name (required)")
	cmdKeyGen.Duration(&keyTTL, "t", "ttl", "Token TTL")
	cmdKeyInit := flaggy.NewSubcommand("init")
	cmdKey.AttachSubcommand(cmdKeyGen, 1)
	cmdKey.AttachSubcommand(cmdKeyInit, 1)

	// Gossip Commands
	cmdGossip := flaggy.NewSubcommand("gossip")
	cmdGossipInit := flaggy.NewSubcommand("init")
	cmdGossipToken := flaggy.NewSubcommand("token")
	cmdGossipToken.String(&gossipService, "s", "service", "Service name (required)")
	cmdGossipToken.Duration(&gossipTTL, "t", "ttl", "Token TTL (default: 720h = 30 days)")
	cmdGossipStatus := flaggy.NewSubcommand("status")

	cmdGossip.AttachSubcommand(cmdGossipInit, 1)
	cmdGossip.AttachSubcommand(cmdGossipToken, 1)
	cmdGossip.AttachSubcommand(cmdGossipStatus, 1)

	// Attach
	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdStart, 1)
	flaggy.AttachSubcommand(cmdStop, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdValidate, 1)
	flaggy.AttachSubcommand(cmdHosts, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)
	flaggy.AttachSubcommand(cmdCert, 1)
	flaggy.AttachSubcommand(cmdKey, 1)
	flaggy.AttachSubcommand(cmdGossip, 1)

	flaggy.Parse()
	welcome()

	// --- Config Resolution ---
	// DO NOT overwrite configPath here yet, or we lose the user's intent.
	// We calculate resolvedPath but only use it for commands that need it immediately.
	resolvedPath, exists := resolveConfigPath(configPath)

	// If user explicitly passed a path that doesn't exist, fail early (except for install/init)
	if configPath != "" && !exists && !cmdInstall.Used {
		logger.Fatal("Config file not found: ", configPath)
	}

	// Bootstrap TLS Env
	if err := tlss.BootstrapEnv(logger); err != nil {
		logger.Warnf("TLS env bootstrap: %v", err)
	}

	// --- Handle Commands that don't need Service Context ---
	if cmdHelp.Used {
		showHelpExamples(resolvedPath)
		return
	}
	if cmdGossip.Used {
		handleGossipCommands(cmdGossipInit.Used, cmdGossipToken.Used, cmdGossipStatus.Used)
		return
	}
	if cmdCert.Used {
		// Cert commands might need config to find cert dir
		configPath = resolvedPath
		handleCertCommands(cmdInstallCA.Used, cmdListCerts.Used, cmdCertInfo.Used)
		return
	}
	if cmdKey.Used {
		configPath = resolvedPath
		handleKeyCommands(cmdKeyInit.Used, cmdKeyGen.Used)
		return
	}
	if cmdValidate.Used {
		logger.Info("Validating configuration...")
		if err := validateConfig(resolvedPath); err != nil {
			logger.Fatal("Configuration validation failed: ", err)
		}
		return
	}
	if cmdHosts.Used {
		logger.Info("Listing configured hosts...")
		if err := listHosts(resolvedPath); err != nil {
			logger.Fatal("Failed to list hosts: ", err)
		}
		return
	}

	// --- Service Configuration ---
	// Define base config. We will tweak this based on Install mode or Platform.
	svcConfig := &service.Config{
		Name:        woos.Name,
		DisplayName: woos.Display,
		Description: woos.Description,
		Arguments:   []string{"run", "-c", resolvedPath}, // Default to resolved path
	}

	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	// Default macOS behavior (Try to detect if root)
	if runtime.GOOS == woos.Darwin {
		if os.Geteuid() == 0 {
			// Root User -> System Daemon
			svcConfig.Option = service.KeyValue{"RunAtLoad": true, "SessionType": "System"}
		} else {
			// Non-Root -> User Agent
			// We must ensure this matches the logic used in the Install block below
			svcConfig.Option = service.KeyValue{"RunAtLoad": true, "UserService": true}

			cwd, _ := os.Getwd()
			configDir := filepath.Dir(resolvedPath)

			// If the config is in the current directory, assume it's the "dev" service
			if configDir == cwd {
				svcConfig.Name = "net.imaxinacion.agbero.dev"
			} else {
				// Otherwise assume it's the standard user service (~/.config/...)
				svcConfig.Name = "net.imaxinacion.agbero"
			}
		}
	} else if runtime.GOOS == woos.Linux {
		// Linux systemd user service support
		if os.Geteuid() != 0 {
			svcConfig.Option = service.KeyValue{"UserService": true}
		}
	}

	prg := &program{
		configPath: resolvedPath, // Default
		devMode:    devMode,
	}

	// --- Handle Install (Interactive) ---
	if cmdInstall.Used {
		var targetConfigPath string
		var targetHostsDir string
		var installType string

		// If user provided flag, trust it
		if configPath != "" {
			targetConfigPath = configPath
			targetHostsDir = filepath.Join(filepath.Dir(configPath), "hosts.d")
		} else {
			// Interactive Form
			userHome, _ := os.UserHomeDir()
			cwd, _ := os.Getwd()

			sysConfig := fmt.Sprintf("/etc/agbero/%s", woos.DefaultConfigName)
			userConfig := filepath.Join(userHome, ".config", "agbero", woos.DefaultConfigName)
			cwdConfig := filepath.Join(cwd, woos.DefaultConfigName)

			form := huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[string]().
						Title("Where should Agbero be installed?").
						Description("Select the configuration location for the service.").
						Options(
							huh.NewOption("System (/etc/agbero) - Requires Sudo", "system"),
							huh.NewOption("User (~/.config/agbero) - No Sudo", "user"),
							huh.NewOption("Current Directory - Testing", "cwd"),
						).
						Value(&installType),
				),
			)

			if err := form.Run(); err != nil {
				logger.Fatal("Installation cancelled")
			}

			switch installType {
			case "system":
				if os.Geteuid() != 0 {
					logger.Fatal("⚠ System installation requires root privileges.\nPlease run: sudo agbero install")
				}
				targetConfigPath = sysConfig
				targetHostsDir = filepath.Join("/etc/agbero", "hosts.d")
				// Service Config is already defaulted to System for root
			case "user":
				targetConfigPath = userConfig
				targetHostsDir = filepath.Join(userHome, ".config", "agbero", "hosts.d")

				// Fix Service Config for User Mode
				if runtime.GOOS == woos.Darwin {
					svcConfig.Name = "net.imaxinacion.agbero"
					svcConfig.Option = service.KeyValue{
						"RunAtLoad":   true,
						"UserService": true, // Force User Service
					}
				} else {
					// Linux User Mode (systemd user)
					svcConfig.Option = service.KeyValue{
						"UserService": true,
					}
				}
			case "cwd":
				targetConfigPath = cwdConfig
				targetHostsDir = filepath.Join(cwd, "hosts.d")
				// CWD is usually for testing, behaves like User mode generally
				if runtime.GOOS == woos.Darwin {
					svcConfig.Name = "net.imaxinacion.agbero.dev"
					svcConfig.Option = service.KeyValue{"RunAtLoad": true, "UserService": true}
				}
			}
		}

		logger.Info("Installing service...")

		// 1. Install Files
		if err := installDefaults(targetConfigPath, targetHostsDir); err != nil {
			logger.Fatal("Failed to setup config files: ", err)
		}

		// 2. Update Service Args to point to new config
		svcConfig.Arguments = []string{"run", "-c", targetConfigPath}
		if devMode {
			svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
		}

		// 3. Create Service Instance with updated config
		s, err := service.New(prg, svcConfig)
		if err != nil {
			logger.Fatal("Failed to init service: ", err)
		}

		// 4. Install
		if err := s.Install(); err != nil {
			logger.Fatal(handleServiceError(err, "install", targetConfigPath))
		}

		logger.Fields("config", targetConfigPath).Info("Service installed successfully")

		if runtime.GOOS == "linux" && installType == "user" {
			logger.Info("To start: systemctl --user start agbero")
		}
		return
	}

	// --- Initialize Service for other commands ---
	// We use the resolved path for Start/Stop/Run logic
	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Fatal("Failed to create service: ", err)
	}

	if cmdStart.Used {
		logger.Info("Starting service...")
		if err := s.Start(); err != nil {
			logger.Fatal(handleServiceError(err, "start", resolvedPath))
		}
		logger.Info("Service started")
		return
	}

	if cmdStop.Used {
		logger.Info("Stopping service...")
		if err := s.Stop(); err != nil {
			logger.Fatal(handleServiceError(err, "stop", resolvedPath))
		}
		logger.Info("Service stopped")
		return
	}

	if cmdUninstall.Used {
		logger.Info("Uninstalling service...")
		// On macOS, we need the correct Name to uninstall properly
		if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
			svcConfig.Name = "net.imaxinacion.agbero"
		}
		// Re-init service just in case
		sUnix, _ := service.New(prg, svcConfig)
		if err := sUnix.Uninstall(); err != nil {
			logger.Fatal(handleServiceError(err, "uninstall", resolvedPath))
		}
		logger.Info("Service uninstalled")
		return
	}

	// --- RUN SERVER ---
	if cmdRun.Used {
		// For run, we rely on resolvedPath being correct
		configPath = resolvedPath

		if err := ensureConfig(configPath); err != nil {
			logger.Fatal("Failed to generate configuration: ", err)
		}

		global, err := loadConfig(configPath)
		if err != nil {
			logger.Fatal("Failed to load config: ", err)
		}

		// Upgrade Logger
		newLogger, cleanup, err := logging.Setup(global.Logging, devMode)
		if err != nil {
			logger.Warn("Failed to setup advanced logging: ", err)
		} else {
			logger = newLogger
			defer cleanup()
		}

		checkAndInstallCA(global)

		logger.Info("Running in interactive mode. Press Ctrl+C to stop.")
		if devMode {
			logger.Level(lx.LevelDebug)
			logger.Warn("Development mode enabled")
		}

		if !service.Interactive() {
			errs := make(chan error, 5)
			_, _ = s.Logger(errs)
			go func() {
				for err := <-errs; err != nil; {
					logger.Errorf("Service internal error: %v", err)
				}
			}()
		}

		if err := s.Run(); err != nil {
			logger.Error("Service exited with error: ", err)
			os.Exit(1)
		}
		return
	}

	showHelpExamples(resolvedPath)
}

// checkAndInstallCA checks if HTTPS is enabled and installs CA root if missing.
func checkAndInstallCA(global *alaye.Global) {
	if len(global.Bind.HTTPS) == 0 {
		return
	}

	installer := tlss.NewInstaller(logger)

	if !tlss.IsCARootInstalled() {
		logger.Info("HTTPS enabled but CA root not found. Auto-installing...")
		if err := installer.InstallCARootIfNeeded(); err != nil {
			logger.Warnf("Failed to auto-install CA root: %v", err)
		} else {
			logger.Info("CA root installed successfully.")
		}
	}
}

// Helper switchers for subcommands
func handleCertCommands(install, list, info bool) {
	installer := tlss.NewInstaller(logger)

	if install {
		if tlss.IsCARootInstalled() && !forceCAInstall {
			logger.Info("CA root certificate is already installed. Use --force to reinstall.")
			return
		}

		logger.Info("Installing CA root certificate...")
		if err := installer.InstallCARootIfNeeded(); err != nil {
			logger.Fatal("Failed to install CA: ", err)
		}
		return
	}

	if list {
		// Attempt to load dir from config
		global, err := loadConfig(configPath)
		if err == nil && global.Storage.CertsDir != "" {
			_ = installer.SetStorageDir(woos.NewFolder(global.Storage.CertsDir))
		}

		certs, err := installer.ListCertificates()
		if err != nil {
			logger.Fatal("Failed to list certs: ", err)
		}
		for i, cert := range certs {
			logger.Printf("%d. %s\n", i+1, cert)
		}
		return
	}

	if info {
		showCertInfo(configPath)
		return
	}

	flaggy.ShowHelpAndExit("cert")
}

func handleKeyCommands(init, gen bool) {
	if init {
		target := "server.key"

		if global, err := loadConfig(configPath); err == nil && &global.Gossip != nil && global.Gossip.PrivateKeyFile != "" {
			target = global.Gossip.PrivateKeyFile
		}

		if err := security.GenerateNewKeyFile(target); err != nil {
			logger.Fatal("Error generating key: ", err)
		}
		logger.Info("Generated private key: ", target)
		return
	}

	if gen {
		if keyService == "" {
			logger.Fatal("Error: --service name is required")
		}

		global, err := loadConfig(configPath)
		if err != nil {
			logger.Fatal("Error loading config: ", err)
		}

		if &global.Gossip == nil || global.Gossip.PrivateKeyFile == "" {
			logger.Fatal("Error: 'gossip.private_key_file' is not set")
		}

		tm, err := security.LoadKeys(global.Gossip.PrivateKeyFile)
		if err != nil {
			logger.Fatal("Error loading private key: ", err)
		}

		token, err := tm.Mint(keyService, keyTTL)
		if err != nil {
			logger.Fatal("Error minting token: ", err)
		}

		logger.Println(token)
		return
	}

	flaggy.ShowHelpAndExit("key")
}

func handleGossipCommands(init, token, status bool) {
	if init {
		handleGossipInit(configPath)
		return
	}
	if token {
		handleGossipToken(configPath)
		return
	}
	if status {
		handleGossipStatus(configPath)
		return
	}
	showGossipHelp()
}
