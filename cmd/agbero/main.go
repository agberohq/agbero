package main

import (
	"os"
	"runtime"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/logging"
	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
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
	// 1. BOOTSTRAP LOGGER: Simple terminal logger for CLI ops until config is loaded
	logger = ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(true))),
		ll.WithFatalExits(true),
	).Enable()

	// Setup Flaggy
	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(version)

	// Global flags
	flaggy.String(&configPath, "c", "config", "Path to configuration file")
	flaggy.Bool(&devMode, "d", "dev", "Enable development mode")
	flaggy.Bool(&enableGossip, "", "gossip", "Enable/disable gossip in run mode")

	// --- Subcommands Setup (Omitted for brevity, remains unchanged) ---
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
	// Add to CLI flags section
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
	resolvedPath, exists := resolveConfigPath(configPath)
	if configPath != "" && !exists {
		logger.Fatal("Config file not found: ", configPath)
	}
	configPath = resolvedPath

	// We need to set CAROOT env var before any TLS/Truststore logic runs.
	// Truststore/mkcert libraries read os.Getenv("CAROOT") at init time.
	if configPath != "" {
		ll.Debug("-------> OVEERKILL ")
		if global, err := loadConfig(configPath); err == nil {
			// Use woos logic to resolve absolute path
			certPath := woos.MakeFolder(global.Storage.CertsDir, woos.CertDir).Path()

			// Create directory if missing (critical for truststore)
			if err := os.MkdirAll(certPath, 0700); err == nil {
				os.Setenv("CAROOT", certPath)
				logger.Debugf("Set CAROOT to %s", certPath)
			}
		}
	}

	// --- Handle Simple Commands (No full config load needed) ---
	if cmdHelp.Used {
		showHelpExamples(configPath)
		return
	}
	if cmdCert.Used {
		handleCertCommands(cmdInstallCA.Used, cmdListCerts.Used, cmdCertInfo.Used)
		return
	}
	if cmdKey.Used {
		handleKeyCommands(cmdKeyInit.Used, cmdKeyGen.Used)
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

	// --- Setup Service Context ---
	svcConfig := &service.Config{
		Name:        "agbero",
		DisplayName: "Agbero Proxy",
		Description: "High-performance reverse proxy",
		Arguments:   []string{"run", "-c", configPath},
	}

	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	if runtime.GOOS == "darwin" {
		if os.Geteuid() == 0 {
			svcConfig.Option = service.KeyValue{"RunAtLoad": true, "SessionType": "System"}
		} else {
			svcConfig.Name = "net.imaxinacion.agbero"
			svcConfig.Option = service.KeyValue{"RunAtLoad": true, "SessionCreate": true}
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
			logger.Fatal(handleServiceError(err, "install", configPath))
		}
		logger.Info("Service installed successfully")
		return
	}

	if cmdStart.Used {
		logger.Info("Starting service...")
		if err := s.Start(); err != nil {
			logger.Fatal(handleServiceError(err, "start", configPath))
		}
		logger.Info("Service started")
		return
	}

	if cmdStop.Used {
		logger.Info("Stopping service...")
		if err := s.Stop(); err != nil {
			logger.Fatal(handleServiceError(err, "stop", configPath))
		}
		logger.Info("Service stopped")
		return
	}

	if cmdUninstall.Used {
		logger.Info("Uninstalling service...")
		if err := s.Uninstall(); err != nil {
			logger.Fatal(handleServiceError(err, "uninstall", configPath))
		}
		logger.Info("Service uninstalled")
		return
	}

	// --- RUN SERVER ---
	if cmdRun.Used {
		// 1. Ensure Config Exists
		if err := ensureConfig(configPath); err != nil {
			logger.Fatal("Failed to generate configuration: ", err)
		}

		// 2. Load Config
		global, err := loadConfig(configPath)
		if err != nil {
			logger.Fatal("Failed to load config: ", err)
		}

		// 3. UPGRADE LOGGER (Apply File/VictoriaLogs config)
		newLogger, cleanup, err := logging.Setup(global.Logging, devMode)
		if err != nil {
			logger.Warn("Failed to setup advanced logging, using terminal only: ", err)
		} else {
			logger = newLogger
			defer cleanup() // FLUSH BUFFERS ON EXIT
		}

		// 4. Auto-Install CA (using upgraded global logger)
		checkAndInstallCA(global)

		logger.Info("Running in interactive mode. Press Ctrl+C to stop.")
		if devMode {
			logger.Level(lx.LevelDebug)
			logger.Warn("Development mode enabled")
		}

		// Silence kardianos/service internal logging if not needed
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

	showHelpExamples(configPath)
}

// checkAndInstallCA checks if HTTPS is enabled and installs CA root if missing
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
	// Use global logger
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
	// Show help if no subcommand specified
	showGossipHelp()
}
