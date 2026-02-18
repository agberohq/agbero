package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/tlss"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
	"golang.org/x/crypto/bcrypt"
)

var (
	logger *ll.Logger
)

// CLI flags
var (
	configPath string
	devMode    bool

	// Install flags
	installHere bool

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

var (
	// Hash Utility Flags
	hashPassword = "admin"
)

func main() {
	// Initialize Single Shutdown Manager
	shutdown := jack.NewShutdown(
		jack.ShutdownWithTimeout(30*time.Second),
		jack.ShutdownWithSignals(os.Interrupt, syscall.SIGTERM),
	)

	// Initialize Logger
	logger = ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout)),
		ll.WithFatalExits(true),
	).Enable()

	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(woos.Version)

	// Global flags
	flaggy.String(&configPath, "c", "config", "Path to configuration file")

	// --- Subcommands ---

	// 1. Install
	cmdInstall := flaggy.NewSubcommand("install")
	cmdInstall.Description = "Install configuration (and system service if applicable)"
	cmdInstall.Bool(&installHere, "", "here", "Install configuration in current directory (skip service install)")

	// 2. Uninstall
	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdUninstall.Description = "Uninstall system service"

	// 3. Service Control
	cmdStart := flaggy.NewSubcommand("start")
	cmdStart.Description = "Start system service"

	cmdStop := flaggy.NewSubcommand("stop")
	cmdStop.Description = "Stop system service"

	// 4. Run
	cmdRun := flaggy.NewSubcommand("run")
	cmdRun.Description = "Run the application (requires existing config)"
	cmdRun.Bool(&devMode, "d", "dev", "Enable development mode")
	cmdRun.Bool(&enableGossip, "", "gossip", "Enable/disable gossip in run mode")

	// 5. Reload
	cmdReload := flaggy.NewSubcommand("reload")
	cmdReload.Description = "Reload configuration of the running service (SIGHUP)"

	// 6. Tools & Helpers
	cmdValidate := flaggy.NewSubcommand("validate")
	cmdValidate.Description = "Validate configuration file"

	cmdHosts := flaggy.NewSubcommand("hosts")
	cmdHosts.Description = "List configured hosts"

	cmdHelp := flaggy.NewSubcommand("help")
	cmdHelp.Description = "Show help examples"

	// Hash command
	cmdHash := flaggy.NewSubcommand("hash")
	cmdHash.Description = "Generate bcrypt hash for passwords"
	cmdHash.String(&hashPassword, "p", "password", "Password to hash")

	// Certificate commands
	cmdCert := flaggy.NewSubcommand("cert")
	cmdCert.Description = "Manage TLS certificates"
	cmdInstallCA := flaggy.NewSubcommand("install")
	cmdInstallCA.Description = "Install CA certificate"
	cmdInstallCA.Bool(&forceCAInstall, "f", "force", "Force reinstall")
	cmdUninstallCA := flaggy.NewSubcommand("uninstall")
	cmdUninstallCA.Description = "Uninstall CA certificate"
	cmdListCerts := flaggy.NewSubcommand("list")
	cmdCertInfo := flaggy.NewSubcommand("info")
	cmdCertInfo.String(&certDir, "d", "dir", "Cert directory")
	cmdCert.AttachSubcommand(cmdInstallCA, 1)
	cmdCert.AttachSubcommand(cmdUninstallCA, 1)
	cmdCert.AttachSubcommand(cmdListCerts, 1)
	cmdCert.AttachSubcommand(cmdCertInfo, 1)

	// Key commands
	cmdKey := flaggy.NewSubcommand("key")
	cmdKeyGen := flaggy.NewSubcommand("gen")
	cmdKeyGen.String(&keyService, "s", "service", "Service name")
	cmdKeyGen.Duration(&keyTTL, "t", "ttl", "Token TTL")
	cmdKeyInit := flaggy.NewSubcommand("init")
	cmdKey.AttachSubcommand(cmdKeyGen, 1)
	cmdKey.AttachSubcommand(cmdKeyInit, 1)

	// Gossip Commands
	cmdGossip := flaggy.NewSubcommand("gossip")
	cmdGossip.Description = "Manage cluster gossip settings"

	cmdGossipInit := flaggy.NewSubcommand("init")
	cmdGossipInit.Description = "Generate private key for auth"

	cmdGossipToken := flaggy.NewSubcommand("token")
	cmdGossipToken.Description = "Generate auth token for a service"
	cmdGossipToken.String(&gossipService, "s", "service", "Service name")
	cmdGossipToken.Duration(&gossipTTL, "t", "ttl", "Token TTL")

	cmdGossipSecret := flaggy.NewSubcommand("secret")
	cmdGossipSecret.Description = "Generate encryption secret_key"

	cmdGossipStatus := flaggy.NewSubcommand("status")
	cmdGossipStatus.Description = "Show current status"

	cmdGossip.AttachSubcommand(cmdGossipInit, 1)
	cmdGossip.AttachSubcommand(cmdGossipToken, 1)
	cmdGossip.AttachSubcommand(cmdGossipSecret, 1) // New
	cmdGossip.AttachSubcommand(cmdGossipStatus, 1)

	// Attach main commands
	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdStart, 1)
	flaggy.AttachSubcommand(cmdStop, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdReload, 1)
	flaggy.AttachSubcommand(cmdValidate, 1)
	flaggy.AttachSubcommand(cmdHosts, 1)
	flaggy.AttachSubcommand(cmdHash, 1)
	flaggy.AttachSubcommand(cmdCert, 1)
	flaggy.AttachSubcommand(cmdKey, 1)
	flaggy.AttachSubcommand(cmdGossip, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)

	flaggy.Parse()

	welcome()

	// --- CONFIG PATH RESOLUTION ---
	var resolvedPath string
	var configExists bool

	// Special handling for Install: We determine where to write
	if cmdInstall.Used {
		path, err := installConfiguration(installHere)
		if err != nil {
			logger.Fatal("Install failed: ", err)
		}

		resolvedPath = path
		configExists = true
	} else {
		resolvedPath, configExists = resolveConfigPath(configPath)
	}

	// Commands that REQUIRE config to exist
	needsConfig := cmdRun.Used || cmdReload.Used || cmdValidate.Used || cmdHosts.Used || cmdStart.Used || (cmdGossip.Used && !cmdGossipSecret.Used) || cmdKey.Used

	if needsConfig && !configExists {
		if strings.TrimSpace(configPath) != "" {
			logger.Fatal("Config file not found at specific path: ", configPath)
		} else {
			logger.Fatal("Config file not found. Run 'agbero install' to generate one.")
		}
	}

	// Bootstrap TLS Env
	if err := tlss.BootstrapEnv(logger); err != nil {
		logger.Warnf("TLS env bootstrap: %v", err)
	}

	if cmdHelp.Used {
		showHelpExamples(resolvedPath)
		return
	}

	if cmdReload.Used {
		if err := reloadService(resolvedPath); err != nil {
			logger.Fatal("Reload failed: ", err)
		}
		logger.Info("Signal sent to process. Check logs for reload status.")
		return
	}

	if cmdHash.Used {
		if hashPassword == "" {
			fmt.Print("Enter password: ")
			fmt.Scanln(&hashPassword)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(hashPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Printf("\n%s\n", string(hash))
		return
	}

	if cmdValidate.Used {
		logger.Info("Validating configuration...")
		if err := validateConfig(resolvedPath); err != nil {
			logger.Fatal("Invalid config: ", err)
		}
		logger.Info("Configuration OK")
		return
	}

	if cmdHosts.Used {
		if err := listHosts(resolvedPath); err != nil {
			logger.Fatal(err)
		}
		return
	}

	// Subcommand Dispatchers
	if cmdCert.Used {
		configPath = resolvedPath
		handleCertCommands(cmdInstallCA.Used, cmdUninstallCA.Used, cmdListCerts.Used, cmdCertInfo.Used)
		return
	}

	if cmdKey.Used {
		configPath = resolvedPath
		handleKeyCommands(cmdKeyInit.Used, cmdKeyGen.Used)
		return
	}

	if cmdGossip.Used {
		configPath = resolvedPath
		// Added cmdGossipSecret.Used to args
		handleGossipCommands(cmdGossipInit.Used, cmdGossipToken.Used, cmdGossipSecret.Used, cmdGossipStatus.Used)
		return
	}

	// --- SERVICE SETUP ---
	svcConfig := &service.Config{
		Name:        woos.Name,
		DisplayName: woos.Display,
		Description: woos.Description,
		Arguments:   []string{"run", "-c", resolvedPath},
	}
	if devMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}

	if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
		cwd, _ := os.Getwd()
		if filepath.Dir(resolvedPath) == cwd {
			svcConfig.Name = "net.imaxinacion.agbero.dev"
		} else {
			svcConfig.Name = "net.imaxinacion.agbero"
		}
		svcConfig.Option = service.KeyValue{"RunAtLoad": true, "UserService": true}
	} else if runtime.GOOS == woos.Linux && os.Geteuid() != 0 {
		svcConfig.Option = service.KeyValue{"UserService": true}
	}

	prg := &program{
		configPath: resolvedPath,
		devMode:    devMode,
		shutdown:   shutdown,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Fatal("Service init failed: ", err)
	}

	if cmdInstall.Used {
		if !installHere {
			logger.Info("Installing system service...")
			if err := s.Install(); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "already exists") {
					logger.Warn("Service already exists.")
				} else {
					logger.Fatal(handleServiceError(err, "install", resolvedPath))
				}
			} else {
				logger.Info("Service installed.")
			}
		} else {
			logger.Info("Local mode: Service registration skipped.")
		}
		return
	}

	if cmdUninstall.Used {
		logger.Info("Uninstalling system service...")
		if err := s.Uninstall(); err != nil {
			logger.Fatal(handleServiceError(err, "uninstall", resolvedPath))
		}
		logger.Info("Service uninstalled.")
		return
	}

	if cmdStart.Used {
		logger.Info("Starting system service...")
		if err := s.Start(); err != nil {
			logger.Fatal(handleServiceError(err, "start", resolvedPath))
		}
		logger.Info("Service started.")
		return
	}

	if cmdStop.Used {
		logger.Info("Stopping system service...")
		if err := s.Stop(); err != nil {
			logger.Fatal(handleServiceError(err, "stop", resolvedPath))
		}
		logger.Info("Service stopped.")
		return
	}

	// --- RUN ---
	if cmdRun.Used {
		global, err := loadConfig(resolvedPath)
		if err != nil {
			logger.Fatal("Failed to load config: ", err)
		}

		newLogger, err := zulu.Logging(&global.Logging, devMode, shutdown)
		if err != nil {
			logger.Warn("Failed to setup advanced logging: ", err)
		} else {
			logger = newLogger
		}

		sighupCh := make(chan os.Signal, 1)
		signal.Notify(sighupCh, syscall.SIGHUP)
		go func() {
			for range sighupCh {
				logger.Info("Received SIGHUP, initiating hot reload...")
				if prg.server != nil {
					prg.server.Reload()
				}
			}
		}()

		logger.Info("Starting agbero...")
		if devMode {
			logger.Level(lx.LevelDebug)
			logger.Warn("Development mode enabled")
		}

		isContainer := os.Getenv("AGBERO_CONTAINER") == "true" || os.Getenv("KUBERNETES_SERVICE_HOST") != ""
		if !service.Interactive() && !isContainer {
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
