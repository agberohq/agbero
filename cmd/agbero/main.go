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

var (
	configPath string
	devMode    bool

	installHere bool

	keyService string
	keyTTL     time.Duration

	forceCAInstall bool
	certDir        string

	// Cluster (formerly Gossip)
	clusterSecret bool

	servePath   string = "."
	servePort   int    = 8000
	serveBind   string
	serveHTTPS  bool
	proxyTarget string
	proxyDomain string
	proxyPort   int = 8080
	proxyBind   string
	proxyHTTPS  bool
)

var (
	hashPassword = "admin"
)

func main() {
	shutdown := jack.NewShutdown(
		jack.ShutdownWithTimeout(30*time.Second),
		jack.ShutdownWithSignals(os.Interrupt, syscall.SIGTERM),
	)

	logger = ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout)),
		ll.WithFatalExits(true),
	).Enable()

	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(woos.Version)

	flaggy.String(&configPath, "c", "config", "Path to configuration file")

	// --- Scaffolding & Service ---
	cmdInit := flaggy.NewSubcommand("init")
	cmdInit.Description = "Scaffold configuration in current directory (no service)"

	cmdInstall := flaggy.NewSubcommand("install")
	cmdInstall.Description = "Install configuration (and system service if applicable)"
	cmdInstall.Bool(&installHere, "", "here", "Install configuration in current directory (skip service install)")

	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdUninstall.Description = "Uninstall system service"

	cmdStart := flaggy.NewSubcommand("start")
	cmdStart.Description = "Start system service"

	cmdStop := flaggy.NewSubcommand("stop")
	cmdStop.Description = "Stop system service"

	cmdRun := flaggy.NewSubcommand("run")
	cmdRun.Description = "Run the application (requires existing config)"
	cmdRun.Bool(&devMode, "d", "dev", "Enable development mode")

	cmdReload := flaggy.NewSubcommand("reload")
	cmdReload.Description = "Reload configuration of the running service (SIGHUP)"

	cmdValidate := flaggy.NewSubcommand("validate")
	cmdValidate.Description = "Validate configuration file"

	cmdHosts := flaggy.NewSubcommand("hosts")
	cmdHosts.Description = "List configured hosts"

	cmdHelp := flaggy.NewSubcommand("help")
	cmdHelp.Description = "Show help examples"

	// --- Ephemeral ---
	cmdServe := flaggy.NewSubcommand("serve")
	cmdServe.Description = "Serve a static directory instantly"
	cmdServe.AddPositionalValue(&servePath, "path", 1, false, "Path to serve (default: current)")
	cmdServe.Int(&servePort, "p", "port", "Port to listen on (default: 8000)")
	cmdServe.String(&serveBind, "b", "bind", "Bind address (default: 0.0.0.0)")
	cmdServe.Bool(&serveHTTPS, "s", "https", "Enable HTTPS (auto-generates certs)")

	cmdProxy := flaggy.NewSubcommand("proxy")
	cmdProxy.Description = "Reverse proxy a local target instantly"
	cmdProxy.AddPositionalValue(&proxyTarget, "target", 1, true, "Target address (e.g. :3000)")
	cmdProxy.AddPositionalValue(&proxyDomain, "domain", 2, false, "Domain name (default: localhost)")
	cmdProxy.Int(&proxyPort, "p", "port", "Port to listen on (default: 8080)")
	cmdProxy.String(&proxyBind, "b", "bind", "Bind address (default: 0.0.0.0)")
	cmdProxy.Bool(&proxyHTTPS, "s", "https", "Enable HTTPS (auto-generates certs)")

	// --- Route Management ---
	cmdRoute := flaggy.NewSubcommand("route")
	cmdRoute.Description = "Manage persistent routes (Interactive)"
	cmdRouteAdd := flaggy.NewSubcommand("add")
	cmdRouteAdd.Description = "Add a new route"
	cmdRouteRemove := flaggy.NewSubcommand("remove")
	cmdRouteRemove.Description = "Remove an existing route"
	cmdRoute.AttachSubcommand(cmdRouteAdd, 1)
	cmdRoute.AttachSubcommand(cmdRouteRemove, 1)

	// --- Utilities ---
	cmdHash := flaggy.NewSubcommand("hash")
	cmdHash.Description = "Generate bcrypt hash for passwords"
	cmdHash.String(&hashPassword, "p", "password", "Password to hash")

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

	// --- API Key Management ---
	cmdKey := flaggy.NewSubcommand("key")
	cmdKey.Description = "Manage API authentication keys"

	cmdKeyGen := flaggy.NewSubcommand("gen")
	cmdKeyGen.Description = "Generate an auth token for an application"
	cmdKeyGen.String(&keyService, "s", "service", "Service identifier")
	cmdKeyGen.Duration(&keyTTL, "t", "ttl", "Token validity duration (default 1y)")

	cmdKeyInit := flaggy.NewSubcommand("init")
	cmdKeyInit.Description = "Generate the master private key for the API"

	cmdKey.AttachSubcommand(cmdKeyGen, 1)
	cmdKey.AttachSubcommand(cmdKeyInit, 1)

	// --- Cluster Management ---
	cmdCluster := flaggy.NewSubcommand("cluster")
	cmdCluster.Description = "Manage cluster settings"

	cmdClusterSecret := flaggy.NewSubcommand("secret")
	cmdClusterSecret.Description = "Generate encryption secret for cluster config"
	cmdCluster.AttachSubcommand(cmdClusterSecret, 1)

	// Attach Top Level
	flaggy.AttachSubcommand(cmdInit, 1)
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
	flaggy.AttachSubcommand(cmdCluster, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)
	flaggy.AttachSubcommand(cmdServe, 1)
	flaggy.AttachSubcommand(cmdProxy, 1)
	flaggy.AttachSubcommand(cmdRoute, 1)

	flaggy.Parse()

	hel := newHelper(logger)
	hel.welcome()

	// --- Handlers ---

	if cmdServe.Used {
		e := &ephemeral{
			logger:   logger,
			shutdown: shutdown,
			path:     servePath,
			bindHost: serveBind,
			port:     servePort,
			useHTTPS: serveHTTPS,
		}
		e.handleServe()
		return
	}

	if cmdProxy.Used {
		e := &ephemeral{
			logger:   logger,
			shutdown: shutdown,
			target:   proxyTarget,
			domain:   proxyDomain,
			bindHost: proxyBind,
			port:     proxyPort,
			useHTTPS: proxyHTTPS,
		}
		e.handleProxy()
		return
	}

	if cmdRoute.Used {
		rm := newRouteManager(logger)
		rm.handleRouteCommands(cmdRouteAdd.Used, cmdRouteRemove.Used, configPath)
		return
	}

	if cmdInit.Used {
		path, err := hel.initConfiguration("")
		if err != nil {
			logger.Fatal("Init failed: ", err)
		}
		logger.Info("Initialized configuration at: ", path)
		return
	}

	var resolvedPath string
	var configExists bool

	if cmdInstall.Used {
		path, err := hel.installConfiguration(installHere)
		if err != nil {
			logger.Fatal("Install failed: ", err)
		}

		resolvedPath = path
		configExists = true
	} else {
		resolvedPath, configExists = hel.resolveConfigPath(configPath)
	}

	needsConfig := cmdRun.Used || cmdReload.Used || cmdValidate.Used || cmdHosts.Used || cmdStart.Used || cmdKey.Used || (cmdCluster.Used && !cmdClusterSecret.Used)

	if needsConfig && !configExists {
		if strings.TrimSpace(configPath) != "" {
			logger.Fatal("Config file not found at specific path: ", configPath)
		} else {
			logger.Fatal("Config file not found. Run 'agbero install' to generate one.")
		}
	}

	if err := tlss.BootstrapEnv(logger); err != nil {
		logger.Warnf("TLS env bootstrap: %v", err)
	}

	if cmdHelp.Used {
		hel.showHelpExamples(resolvedPath)
		return
	}

	if cmdReload.Used {
		if err := hel.reloadService(resolvedPath); err != nil {
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
		if err := hel.validateConfig(resolvedPath); err != nil {
			logger.Fatal("Invalid config: ", err)
		}
		logger.Info("Configuration OK")
		return
	}

	if cmdHosts.Used {
		if err := hel.listHosts(resolvedPath); err != nil {
			logger.Fatal(err)
		}
		return
	}

	if cmdCert.Used {
		hel.handleCertCommands(cmdInstallCA.Used, cmdUninstallCA.Used, cmdListCerts.Used, cmdCertInfo.Used, forceCAInstall, certDir)
		return
	}

	if cmdKey.Used {
		hel.handleKeyCommands(cmdKeyInit.Used, cmdKeyGen.Used, keyService, keyTTL)
		return
	}

	if cmdCluster.Used {
		if cmdClusterSecret.Used {
			hel.handleClusterSecret()
			return
		}
		flaggy.ShowHelpAndExit("cluster")
		return
	}

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
					logger.Fatal(hel.handleServiceError(err, "install", resolvedPath))
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
			logger.Fatal(hel.handleServiceError(err, "uninstall", resolvedPath))
		}
		logger.Info("Service uninstalled.")
		return
	}

	if cmdStart.Used {
		logger.Info("Starting system service...")
		if err := s.Start(); err != nil {
			logger.Fatal(hel.handleServiceError(err, "start", resolvedPath))
		}
		logger.Info("Service started.")
		return
	}

	if cmdStop.Used {
		logger.Info("Stopping system service...")
		if err := s.Stop(); err != nil {
			logger.Fatal(hel.handleServiceError(err, "stop", resolvedPath))
		}
		logger.Info("Service stopped.")
		return
	}

	if cmdRun.Used {
		global, err := hel.loadConfig(resolvedPath)
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

	hel.showHelpExamples(resolvedPath)
}
