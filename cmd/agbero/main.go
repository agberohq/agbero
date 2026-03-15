package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agberohq/agbero/cmd/agbero/helper"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/charmbracelet/huh"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

var logger *ll.Logger

func main() {
	logger = ll.New(woos.Name,
		ll.WithHandler(lh.NewColorizedHandler(os.Stdout)),
		ll.WithFatalExits(true),
	).Enable()

	shutdown := jack.NewShutdown(
		jack.ShutdownWithTimeout(10*time.Second),
		jack.ShutdownWithSignals(os.Interrupt, syscall.SIGTERM),
		jack.ShutdownWithLogger(logger),
		jack.ShutdownConcurrent(),
	)

	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(woos.Version)

	cfg := &helper.Config{
		ServePath: ".",
		ServePort: 8000,
		ProxyPort: 8080,
	}

	flaggy.String(&cfg.ConfigPath, "c", "config", "Path to configuration file")

	cmdInit := flaggy.NewSubcommand("init")
	cmdInit.Description = "Scaffold configuration in current directory"

	cmdConfig := flaggy.NewSubcommand("config")
	cmdConfig.Description = "Configuration management"

	cmdConfigValidate := flaggy.NewSubcommand("validate")
	cmdConfigValidate.Description = "Validate configuration file"

	cmdConfigReload := flaggy.NewSubcommand("reload")
	cmdConfigReload.Description = "Hot-reload the running agbero instance (SIGHUP)"

	cmdConfigView := flaggy.NewSubcommand("view")
	cmdConfigView.Description = "Print the configuration file"
	var configViewEditor string
	cmdConfigView.String(&configViewEditor, "e", "editor", "Open in a specific editor (vim, nano, cat …)")

	cmdConfigPath := flaggy.NewSubcommand("path")
	cmdConfigPath.Description = "Show the resolved config file path"

	cmdConfigEdit := flaggy.NewSubcommand("edit")
	cmdConfigEdit.Description = "Open the configuration file in $EDITOR"

	cmdConfig.AttachSubcommand(cmdConfigValidate, 1)
	cmdConfig.AttachSubcommand(cmdConfigReload, 1)
	cmdConfig.AttachSubcommand(cmdConfigView, 1)
	cmdConfig.AttachSubcommand(cmdConfigPath, 1)
	cmdConfig.AttachSubcommand(cmdConfigEdit, 1)

	cmdSecret := flaggy.NewSubcommand("secret")
	cmdSecret.Description = "Generate secrets, keys, and tokens"

	cmdSecretCluster := flaggy.NewSubcommand("cluster")
	cmdSecretCluster.Description = "Generate AES-256 gossip secret key"

	cmdSecretKey := flaggy.NewSubcommand("key")
	cmdSecretKey.Description = "Manage internal auth keys"

	cmdSecretKeyInit := flaggy.NewSubcommand("init")
	cmdSecretKeyInit.Description = "Generate the master private key for internal auth"
	cmdSecretKey.AttachSubcommand(cmdSecretKeyInit, 1)

	cmdSecretToken := flaggy.NewSubcommand("token")
	cmdSecretToken.Description = "Generate a signed API token for a service"
	cmdSecretToken.String(&cfg.KeyService, "s", "service", "Service identifier")
	cmdSecretToken.Duration(&cfg.KeyTTL, "t", "ttl", "Token validity duration (default 1y)")

	cmdSecretHash := flaggy.NewSubcommand("hash")
	cmdSecretHash.Description = "Generate a bcrypt hash of a password"
	cmdSecretHash.String(&cfg.HashPassword, "p", "password", "Password to hash")

	cmdSecretPassword := flaggy.NewSubcommand("password")
	cmdSecretPassword.Description = "Generate a random password and its bcrypt hash"
	cmdSecretPassword.AddPositionalValue(&cfg.PasswordLength, "length", 1, false, "Password length (default: 32)")

	cmdSecret.AttachSubcommand(cmdSecretCluster, 1)
	cmdSecret.AttachSubcommand(cmdSecretKey, 1)
	cmdSecret.AttachSubcommand(cmdSecretToken, 1)
	cmdSecret.AttachSubcommand(cmdSecretHash, 1)
	cmdSecret.AttachSubcommand(cmdSecretPassword, 1)

	cmdHost := flaggy.NewSubcommand("host")
	cmdHost.Description = "Manage hosts and routes"

	cmdHostList := flaggy.NewSubcommand("list")
	cmdHostList.Description = "List all configured hosts"

	cmdHostAdd := flaggy.NewSubcommand("add")
	cmdHostAdd.Description = "Add a new host/route (interactive)"

	cmdHostRemove := flaggy.NewSubcommand("remove")
	cmdHostRemove.Description = "Remove a host/route (interactive)"

	cmdHost.AttachSubcommand(cmdHostList, 1)
	cmdHost.AttachSubcommand(cmdHostAdd, 1)
	cmdHost.AttachSubcommand(cmdHostRemove, 1)

	cmdCert := flaggy.NewSubcommand("cert")
	cmdCert.Description = "Manage TLS certificates"

	cmdCertInstall := flaggy.NewSubcommand("install")
	cmdCertInstall.Description = "Install CA certificate"
	cmdCertInstall.Bool(&cfg.ForceCAInstall, "f", "force", "Force reinstall")

	cmdCertUninstall := flaggy.NewSubcommand("uninstall")
	cmdCertUninstall.Description = "Uninstall CA certificate"

	cmdCertList := flaggy.NewSubcommand("list")
	cmdCertList.Description = "List managed certificates"

	cmdCertInfo := flaggy.NewSubcommand("info")
	cmdCertInfo.Description = "Show certificate store information"
	cmdCertInfo.String(&cfg.CertDir, "d", "dir", "Cert directory")

	cmdCert.AttachSubcommand(cmdCertInstall, 1)
	cmdCert.AttachSubcommand(cmdCertUninstall, 1)
	cmdCert.AttachSubcommand(cmdCertList, 1)
	cmdCert.AttachSubcommand(cmdCertInfo, 1)

	cmdService := flaggy.NewSubcommand("service")
	cmdService.Description = "Manage the system service"

	cmdServiceInstall := flaggy.NewSubcommand("install")
	cmdServiceInstall.Description = "Install configuration and system service"
	cmdServiceInstall.Bool(&cfg.InstallHere, "", "here", "Install config in current directory only")

	cmdServiceUninstall := flaggy.NewSubcommand("uninstall")
	cmdServiceUninstall.Description = "Uninstall system service"

	cmdServiceStart := flaggy.NewSubcommand("start")
	cmdServiceStart.Description = "Start system service"

	cmdServiceStop := flaggy.NewSubcommand("stop")
	cmdServiceStop.Description = "Stop system service"

	cmdServiceRestart := flaggy.NewSubcommand("restart")
	cmdServiceRestart.Description = "Restart system service"

	cmdServiceStatus := flaggy.NewSubcommand("status")
	cmdServiceStatus.Description = "Check system service status"

	cmdService.AttachSubcommand(cmdServiceInstall, 1)
	cmdService.AttachSubcommand(cmdServiceUninstall, 1)
	cmdService.AttachSubcommand(cmdServiceStart, 1)
	cmdService.AttachSubcommand(cmdServiceStop, 1)
	cmdService.AttachSubcommand(cmdServiceRestart, 1)
	cmdService.AttachSubcommand(cmdServiceStatus, 1)

	cmdCluster := flaggy.NewSubcommand("cluster")
	cmdCluster.Description = "Manage cluster settings"

	cmdClusterStart := flaggy.NewSubcommand("start")
	cmdClusterStart.Description = "Start agbero as a cluster seed node"

	cmdClusterJoin := flaggy.NewSubcommand("join")
	cmdClusterJoin.Description = "Join an existing agbero cluster"
	cmdClusterJoin.AddPositionalValue(&cfg.ClusterJoinIP, "ip", 1, true, "IP address of the cluster seed")
	cmdClusterJoin.String(&cfg.ClusterSecret, "s", "secret", "Cluster secret key")

	cmdCluster.AttachSubcommand(cmdClusterStart, 1)
	cmdCluster.AttachSubcommand(cmdClusterJoin, 1)

	cmdRun := flaggy.NewSubcommand("run")
	cmdRun.Description = "Run agbero using the discovered config"
	cmdRun.Bool(&cfg.DevMode, "d", "dev", "Enable development mode")

	cmdHome := flaggy.NewSubcommand("home")
	cmdHome.Description = "Print or navigate to the agbero configuration directory"
	var homeTarget, homeAction string
	cmdHome.AddPositionalValue(&homeTarget, "target", 1, false, "hosts, certs, data, logs, work, config, or @ to open shell")
	cmdHome.AddPositionalValue(&homeAction, "action", 2, false, "Use '@' to open a shell in the target directory")

	cmdServe := flaggy.NewSubcommand("serve")
	cmdServe.Description = "Serve a static directory instantly"
	cmdServe.AddPositionalValue(&cfg.ServePath, "path", 1, false, "Path to serve (default: .)")
	cmdServe.Int(&cfg.ServePort, "p", "port", "Port (default: 8000)")
	cmdServe.String(&cfg.ServeBind, "b", "bind", "Bind address")
	cmdServe.Bool(&cfg.ServeHTTPS, "s", "https", "Enable HTTPS")

	cmdProxy := flaggy.NewSubcommand("proxy")
	cmdProxy.Description = "Reverse-proxy a local target instantly"
	cmdProxy.AddPositionalValue(&cfg.ProxyTarget, "target", 1, true, "Target address (e.g. :3000)")
	cmdProxy.AddPositionalValue(&cfg.ProxyDomain, "domain", 2, false, "Domain name (default: localhost)")
	cmdProxy.Int(&cfg.ProxyPort, "p", "port", "Port (default: 8080)")
	cmdProxy.String(&cfg.ProxyBind, "b", "bind", "Bind address")
	cmdProxy.Bool(&cfg.ProxyHTTPS, "s", "https", "Enable HTTPS")

	cmdHelp := flaggy.NewSubcommand("help")
	cmdHelp.Description = "Show usage examples"

	flaggy.AttachSubcommand(cmdInit, 1)
	flaggy.AttachSubcommand(cmdConfig, 1)
	flaggy.AttachSubcommand(cmdSecret, 1)
	flaggy.AttachSubcommand(cmdHost, 1)
	flaggy.AttachSubcommand(cmdCert, 1)
	flaggy.AttachSubcommand(cmdService, 1)
	flaggy.AttachSubcommand(cmdCluster, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdHome, 1)
	flaggy.AttachSubcommand(cmdServe, 1)
	flaggy.AttachSubcommand(cmdProxy, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)

	flaggy.Parse()

	hel := helper.New(logger, shutdown, cfg)

	if cmdHome.Used {
		hel.Home().Navigate(homeTarget, homeAction)
		return
	}

	welcome()

	if cmdServe.Used {
		hel.Ephemeral().Serve()
		return
	}

	if cmdProxy.Used {
		hel.Ephemeral().Proxy()
		return
	}

	if cmdSecret.Used {
		s := hel.Secret()
		switch {
		case cmdSecretCluster.Used:
			s.Cluster()
		case cmdSecretKey.Used && cmdSecretKeyInit.Used:
			resolvedPath, _ := helper.ResolveConfigPath(cfg.ConfigPath)
			s.KeyInit(resolvedPath)
		case cmdSecretToken.Used:
			resolvedPath, _ := helper.ResolveConfigPath(cfg.ConfigPath)
			s.Token(resolvedPath, cfg.KeyService, cfg.KeyTTL)
		case cmdSecretHash.Used:
			s.Hash(cfg.HashPassword)
		case cmdSecretPassword.Used:
			length := 0
			if cfg.PasswordLength != "" {
				if n, err := strconv.Atoi(cfg.PasswordLength); err == nil {
					length = n
				} else {
					logger.Fatal("invalid length: must be a number")
				}
			}
			s.Password(length)
		default:
			flaggy.ShowHelpAndExit("secret")
		}
		return
	}

	if cmdInit.Used {
		path, err := helper.InitConfiguration("")
		if err != nil {
			logger.Fatal("init failed: ", err)
		}
		logger.Info("initialized configuration at: ", path)
		return
	}

	var resolvedPath string
	var configExists bool

	if cmdServiceInstall.Used {
		path, err := helper.InstallConfiguration(cfg.InstallHere)
		if err != nil {
			logger.Fatal("install failed: ", err)
		}
		resolvedPath = path
		configExists = true
	} else {
		resolvedPath, configExists = helper.ResolveConfigPath(cfg.ConfigPath)
	}

	needsConfig := cmdRun.Used || cmdConfig.Used || cmdHost.Used ||
		cmdServiceStart.Used || cmdClusterStart.Used || cmdClusterJoin.Used

	if needsConfig && !configExists {
		if strings.TrimSpace(cfg.ConfigPath) != "" {
			logger.Fatal("config file not found at: ", cfg.ConfigPath)
		} else {
			ctx := installer.NewContext(logger, "")
			if ctx.Interactive {
				var doInit bool
				err := huh.NewConfirm().
					Title("Configuration Not Found").
					Description("No agbero.hcl found. Would you like to initialize one?").
					Value(&doInit).
					Run()
				if err == nil && doInit {
					path, err := helper.InitConfiguration("")
					if err != nil {
						logger.Fatal("init failed: ", err)
					}
					resolvedPath = path
					configExists = true
				} else {
					logger.Fatal("config file required. Run 'agbero init' first.")
				}
			} else {
				logger.Fatal("config file not found. Run 'agbero service install' to generate one.")
			}
		}
	}

	if err := tlss.BootstrapEnv(logger); err != nil {
		logger.Warnf("TLS env bootstrap: %v", err)
	}

	if cmdConfig.Used {
		ch := hel.Config()
		switch {
		case cmdConfigValidate.Used:
			logger.Info("validating configuration...")
			if err := ch.Validate(resolvedPath); err != nil {
				logger.Fatal("invalid config: ", err)
			}
			logger.Info("configuration OK")
		case cmdConfigReload.Used:
			if err := ch.Reload(resolvedPath); err != nil {
				logger.Fatal("reload failed: ", err)
			}
			logger.Info("signal sent. Check logs for reload status.")
		case cmdConfigView.Used:
			ch.View(resolvedPath, configViewEditor)
		case cmdConfigPath.Used:
			ch.Path(resolvedPath)
		case cmdConfigEdit.Used:
			ch.Edit(resolvedPath)
		default:
			flaggy.ShowHelpAndExit("config")
		}
		return
	}

	if cmdHost.Used {
		hh := hel.Host()
		hh.ProxyTpl = proxyTpl
		hh.StaticTpl = staticTpl
		hh.TCPTpl = tcpTpl
		switch {
		case cmdHostList.Used:
			if err := hh.List(resolvedPath); err != nil {
				logger.Fatal(err)
			}
		case cmdHostAdd.Used:
			hh.Add(resolvedPath)
		case cmdHostRemove.Used:
			hh.Remove(resolvedPath)
		default:
			flaggy.ShowHelpAndExit("host")
		}
		return
	}

	if cmdCert.Used {
		ch := hel.Cert()
		switch {
		case cmdCertInstall.Used:
			ch.Install(resolvedPath, cfg.ForceCAInstall)
		case cmdCertUninstall.Used:
			ch.Uninstall(resolvedPath)
		case cmdCertList.Used:
			ch.List(resolvedPath)
		case cmdCertInfo.Used:
			ch.Info(resolvedPath)
		default:
			flaggy.ShowHelpAndExit("cert")
		}
		return
	}

	svcConfig := &service.Config{
		Name:        woos.Name,
		DisplayName: woos.Display,
		Description: woos.Description,
		Arguments:   []string{"run", "-c", resolvedPath},
	}
	if cfg.DevMode {
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
		configPath:    resolvedPath,
		devMode:       cfg.DevMode,
		shutdown:      shutdown,
		clusterStart:  cmdClusterStart.Used,
		clusterJoinIP: cfg.ClusterJoinIP,
		clusterSecret: cfg.ClusterSecret,
	}

	svc, err := service.New(prg, svcConfig)
	if err != nil {
		logger.Fatal("service init failed: ", err)
	}

	if cmdService.Used {
		sh := hel.Service()
		switch {
		case cmdServiceInstall.Used:
			sh.Install(svc, cfg.InstallHere)
		case cmdServiceUninstall.Used:
			sh.Uninstall(svc)
		case cmdServiceStart.Used:
			sh.Start(svc)
		case cmdServiceStop.Used:
			sh.Stop(svc)
		case cmdServiceRestart.Used:
			sh.Restart(svc)
		case cmdServiceStatus.Used:
			sh.Status(svc, resolvedPath)
		default:
			flaggy.ShowHelpAndExit("service")
		}
		return
	}

	if cmdRun.Used || cmdClusterStart.Used || cmdClusterJoin.Used {
		global, err := loadConfig(resolvedPath)
		if err != nil {
			logger.Fatal("failed to load config: ", err)
		}
		newLogger, err := zulu.Logging(&global.Logging, cfg.DevMode, shutdown)
		if err != nil {
			logger.Warn("failed to setup advanced logging: ", err)
		} else {
			logger = newLogger
		}

		sighupCh := make(chan os.Signal, 1)
		signal.Notify(sighupCh, syscall.SIGHUP)
		go func() {
			for range sighupCh {
				logger.Info("received SIGHUP, initiating hot reload...")
				if prg.server != nil {
					prg.server.Reload()
				}
			}
		}()

		if cfg.DevMode {
			logger.Level(lx.LevelDebug)
			logger.Warn("development mode enabled")
		}

		isContainer := os.Getenv("AGBERO_CONTAINER") == "true" || os.Getenv("KUBERNETES_SERVICE_HOST") != ""
		if !service.Interactive() && !isContainer {
			errs := make(chan error, 5)
			_, _ = svc.Logger(errs)
			go func() {
				for e := range errs {
					logger.Errorf("service internal error: %v", e)
				}
			}()
		}

		if err := svc.Run(); err != nil {
			logger.Error("service exited with error: ", err)
			os.Exit(1)
		}
		return
	}

	if cmdHelp.Used {
		showHelpExamples()
		return
	}

	showHelpExamples()
}

func welcome() {
	fmt.Println(installer.BannerTmpl)
	fmt.Printf("\033[1;34m%s\033[0m - %s\n", woos.Name, woos.Description)
	fmt.Printf("\033[90mVersion: %s\033[0m\n", woos.Version)
	fmt.Printf("\033[90mDate: %s\033[0m\n\n", woos.Date)
}

func showHelpExamples() {
	exeName := woos.Name
	if len(os.Args) > 0 {
		exeName = filepath.Base(os.Args[0])
	}
	prefix := "sudo "
	if runtime.GOOS == woos.Windows {
		prefix = ""
	}
	fmt.Printf("\n%s - %s v%s\n", woos.Name, woos.Description, woos.Version)
	fmt.Println("\n===============================================================")
	fmt.Println("USAGE EXAMPLES")
	fmt.Println("===============================================================")
	fmt.Printf("\nSCAFFOLDING:\n")
	fmt.Printf("  %s init                        # scaffold config in current folder\n", exeName)
	fmt.Printf("  %s service install             # install config + system service\n", exeName)
	fmt.Printf("\nEXECUTION:\n")
	fmt.Printf("  %s run                         # run using discovered config\n", exeName)
	fmt.Printf("  %s serve .                     # serve current directory on the fly\n", exeName)
	fmt.Printf("  %s proxy :3000                 # proxy local port 3000\n", exeName)
	fmt.Printf("\nCONFIGURATION:\n")
	fmt.Printf("  %s config validate             # validate config file\n", exeName)
	fmt.Printf("  %s config view                 # print config file\n", exeName)
	fmt.Printf("  %s config edit                 # edit config in $EDITOR\n", exeName)
	fmt.Printf("  %s config path                 # show config file path\n", exeName)
	fmt.Printf("  %s config reload               # hot reload running instance\n", exeName)
	fmt.Printf("\nSECRETS & KEYS:\n")
	fmt.Printf("  %s secret cluster              # generate gossip secret key\n", exeName)
	fmt.Printf("  %s secret key init             # generate internal auth key\n", exeName)
	fmt.Printf("  %s secret token -s myapp       # generate API token for 'myapp'\n", exeName)
	fmt.Printf("  %s secret hash -p mypass       # bcrypt hash a password\n", exeName)
	fmt.Printf("  %s secret password             # generate random password + hash\n", exeName)
	fmt.Printf("\nHOSTS:\n")
	fmt.Printf("  %s host list                   # list configured hosts\n", exeName)
	fmt.Printf("  %s host add                    # add host/route (interactive)\n", exeName)
	fmt.Printf("  %s host remove                 # remove host/route (interactive)\n", exeName)
	fmt.Printf("\nNAVIGATION:\n")
	fmt.Printf("  %s home                        # print Agbero home directory\n", exeName)
	fmt.Printf("  %s home @                      # open shell in home directory\n", exeName)
	fmt.Printf("  %s home hosts @                # open shell in hosts.d\n", exeName)
	fmt.Printf("\nSERVICE MANAGEMENT:\n")
	fmt.Printf("  %s%s service install\n", prefix, exeName)
	fmt.Printf("  %s%s service start\n", prefix, exeName)
	fmt.Printf("  %s%s service stop\n", prefix, exeName)
	fmt.Printf("  %s%s service restart\n", prefix, exeName)
	fmt.Printf("  %s%s service status\n", prefix, exeName)
	fmt.Printf("  %s%s service uninstall\n", prefix, exeName)
}
