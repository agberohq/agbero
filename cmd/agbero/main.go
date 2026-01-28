package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/logging"
	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/charmbracelet/huh"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
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

	// --- Subcommands ---
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

	// Resolve config path (do not overwrite user intent yet)
	resolvedPath, exists := resolveConfigPath(configPath)

	// If user explicitly passed a path that doesn't exist, fail early (except install)
	if strings.TrimSpace(configPath) != "" && !exists && !cmdInstall.Used {
		logger.Fatal("Config file not found: ", resolvedPath)
	}

	// Bootstrap TLS Env (PATH, cert tools, etc.)
	if err := tlss.BootstrapEnv(logger); err != nil {
		logger.Warnf("TLS env bootstrap: %v", err)
	}

	// --- Commands that don't need service context ---
	if cmdHelp.Used {
		showHelpExamples(resolvedPath)
		return
	}
	if cmdGossip.Used {
		configPath = resolvedPath
		handleGossipCommands(cmdGossipInit.Used, cmdGossipToken.Used, cmdGossipStatus.Used)
		return
	}
	if cmdCert.Used {
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

	// --- Default service config (will be adjusted per OS + install mode) ---
	svcConfig := &service.Config{
		Name:        woos.Name,
		DisplayName: woos.Display,
		Description: woos.Description,
		Arguments:   []string{"run", "-c", resolvedPath},
	}

	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	// macOS name selection for user services (so "cwd dev" doesn't collide)
	if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
		cwd, _ := os.Getwd()
		if filepath.Dir(resolvedPath) == cwd {
			svcConfig.Name = "net.imaxinacion.agbero.dev"
		} else {
			svcConfig.Name = "net.imaxinacion.agbero"
		}
		svcConfig.Option = service.KeyValue{"RunAtLoad": true, "UserService": true}
	}

	// Linux user service support
	if runtime.GOOS == woos.Linux && os.Geteuid() != 0 {
		svcConfig.Option = service.KeyValue{"UserService": true}
	}

	prg := &program{
		configPath: resolvedPath,
		devMode:    devMode,
	}

	// --- INSTALL (Interactive) ---
	if cmdInstall.Used {
		targetConfigPath, installType := pickInstallConfigPath(resolvedPath, configPath)

		// Ensure config + directories exist
		if err := ensureConfig(targetConfigPath); err != nil {
			logger.Fatal("Failed to setup config files: ", err)
		}

		// Adjust service config based on target
		svcConfig.Arguments = []string{"run", "-c", targetConfigPath}
		if devMode {
			svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
		}

		// macOS: ensure Name matches target
		if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
			cwd, _ := os.Getwd()
			if filepath.Dir(targetConfigPath) == cwd {
				svcConfig.Name = "net.imaxinacion.agbero.dev"
			} else {
				svcConfig.Name = "net.imaxinacion.agbero"
			}
			svcConfig.Option = service.KeyValue{"RunAtLoad": true, "UserService": true}
		}

		// Create service instance
		s, err := service.New(prg, svcConfig)
		if err != nil {
			logger.Fatal("Failed to init service: ", err)
		}

		logger.Info("Installing service...")

		// If already installed, uninstall then install (solves the .plist already exists case)
		if err := s.Install(); err != nil {
			// kardianos/service on macOS often reports: "Init already exists: <plist>"
			if strings.Contains(strings.ToLower(err.Error()), "already exists") {
				logger.Warn("Service already exists, attempting to replace it...")
				_ = s.Stop()
				_ = s.Uninstall()
				if err2 := s.Install(); err2 != nil {
					logger.Fatal(handleServiceError(err2, "install", targetConfigPath))
				}
			} else {
				logger.Fatal(handleServiceError(err, "install", targetConfigPath))
			}
		}

		logger.Fields("config", targetConfigPath, "mode", installType).Info("Service installed successfully")

		if runtime.GOOS == "linux" && installType == "user" {
			logger.Info("To start: systemctl --user start agbero")
		}
		return
	}

	// --- Initialize service for start/stop/uninstall/run ---
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

		// On macOS user installs, Name must match what we used during install
		if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
			cwd, _ := os.Getwd()
			if filepath.Dir(resolvedPath) == cwd {
				svcConfig.Name = "net.imaxinacion.agbero.dev"
			} else {
				svcConfig.Name = "net.imaxinacion.agbero"
			}
			s2, _ := service.New(prg, svcConfig)
			_ = s2.Stop()
			if err := s2.Uninstall(); err != nil {
				logger.Fatal(handleServiceError(err, "uninstall", resolvedPath))
			}
			logger.Info("Service uninstalled")
			return
		}

		_ = s.Stop()
		if err := s.Uninstall(); err != nil {
			logger.Fatal(handleServiceError(err, "uninstall", resolvedPath))
		}
		logger.Info("Service uninstalled")
		return
	}

	// --- RUN SERVER ---
	if cmdRun.Used {
		configPath = resolvedPath

		// Ensure config + layout
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

		logger.Info("Running in interactive mode. Press Ctrl+C to stop.")
		if devMode {
			logger.Level(lx.LevelDebug)
			logger.Warn("Development mode enabled")
		}

		if !service.Interactive() {
			errs := make(chan error, 5)
			_, _ = s.Logger(errs)
			go func() {
				for err := range errs {
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

// pickInstallConfigPath selects the target config path for install.
func pickInstallConfigPath(resolvedPath, flagPath string) (targetConfigPath string, installType string) {
	if strings.TrimSpace(flagPath) != "" {
		// user explicitly selected path; we install “next to it”
		return resolvedPath, "custom"
	}

	userHome, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	sysConfig := filepath.Join("/etc", woos.Name, woos.DefaultConfigName)
	userConfig := filepath.Join(userHome, ".config", woos.Name, woos.DefaultConfigName)
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
		return sysConfig, "system"
	case "user":
		return userConfig, "user"
	case "cwd":
		return cwdConfig, "cwd"
	default:
		return userConfig, "user"
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

		global, err := loadConfig(configPath)
		if err == nil && global.Gossip.PrivateKeyFile != "" {
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

		if global.Gossip.PrivateKeyFile == "" {
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
