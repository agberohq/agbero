package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"charm.land/huh/v2"
	"github.com/agberohq/agbero/cmd/agbero/helper"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/agberohq/agbero/internal/pkg/ui"
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
	cmdServiceUninstall.Description = "Uninstall system service (use --all to remove everything)"
	cmdServiceUninstall.Bool(&cfg.UninstallAll, "", "all", "Remove service, CA, all data, and binary")
	cmdServiceUninstall.Bool(&cfg.UninstallForce, "", "force", "Skip confirmation prompt")

	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdUninstall.Description = "Uninstall everything (service, CA, configurations, data, and binary)"
	cmdUninstall.Bool(&cfg.UninstallForce, "", "force", "Skip confirmation prompt")

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

	cmdSystem := flaggy.NewSubcommand("system")
	cmdSystem.Description = "System-level operations (backup, restore, etc.)"

	cmdSystemBackup := flaggy.NewSubcommand("backup")
	cmdSystemBackup.Description = "Backup configurations, certificates, and data to a password-protected zip"
	cmdSystemBackup.String(&cfg.SystemOut, "o", "out", "Output zip file path (default: agbero_backup_<timestamp>.zip)")
	cmdSystemBackup.String(&cfg.SystemPass, "p", "password", "Password for AES-256 encryption")

	cmdSystemRestore := flaggy.NewSubcommand("restore")
	cmdSystemRestore.Description = "Restore configurations, certificates, and data from a backup zip"
	cmdSystemRestore.String(&cfg.SystemIn, "i", "in", "Input zip file path")
	cmdSystemRestore.String(&cfg.SystemPass, "p", "password", "Password for AES-256 decryption")
	cmdSystemRestore.Bool(&cfg.SystemForce, "f", "force", "Force overwrite of existing files without prompting")

	cmdSystem.AttachSubcommand(cmdSystemBackup, 1)
	cmdSystem.AttachSubcommand(cmdSystemRestore, 1)

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
	cmdServe.Bool(&cfg.ServeMarkdown, "m", "markdown", "Render .md files as HTML")
	cmdServe.Bool(&cfg.ServeSPA, "spa", "spa", "Render Single Page Applications as HTML (default: false)")
	cmdServe.String(&cfg.ServePHP, "php", "php", "Render PHP files as HTML (default: false)")

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
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdCluster, 1)
	flaggy.AttachSubcommand(cmdSystem, 1)
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

	if cmdSystem.Used {
		if cmdSystemBackup.Used {
			resolvedPath, _ := helper.ResolveConfigPath(logger, cfg.ConfigPath)
			hel.System().Backup(resolvedPath, cfg.SystemOut, cfg.SystemPass)
			return
		}
		if cmdSystemRestore.Used {
			hel.System().Restore(cfg.SystemIn, cfg.SystemPass, cfg.SystemForce)
			return
		}
	}

	if cmdSecret.Used {
		s := hel.Secret()
		switch {
		case cmdSecretCluster.Used:
			s.Cluster()
		case cmdSecretKey.Used && cmdSecretKeyInit.Used:
			resolvedPath, _ := helper.ResolveConfigPath(logger, cfg.ConfigPath)
			s.KeyInit(resolvedPath)
		case cmdSecretToken.Used:
			resolvedPath, _ := helper.ResolveConfigPath(logger, cfg.ConfigPath)
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
		if _, err := helper.InitConfiguration(logger, ""); err != nil {
			logger.Fatal("init failed: ", err)
		}
		return
	}

	var resolvedPath string
	var configExists bool

	if cmdServiceInstall.Used {
		if strings.TrimSpace(cfg.ConfigPath) != "" {
			resolvedPath, configExists = helper.ResolveConfigPath(logger, cfg.ConfigPath)
			if !configExists {
				logger.Fatalf("provided config file not found: %s", cfg.ConfigPath)
			}
		} else {
			path, err := helper.InstallConfiguration(logger, cfg.InstallHere)
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					logger.Info(err.Error() + " — skipping initialization.")
					resolvedPath = path
					configExists = true
				} else {
					logger.Fatal("install failed: ", err)
				}
			} else {
				resolvedPath = path
				configExists = true
			}
		}
	} else {
		resolvedPath, configExists = helper.ResolveConfigPath(logger, cfg.ConfigPath)
	}

	if cmdUninstall.Used {
		svcConfig := &service.Config{
			Name:        woos.Name,
			DisplayName: woos.Display,
			Description: woos.Description,
		}
		svc, _ := service.New(nil, svcConfig)
		hel.Home().Uninstall(svc, resolvedPath, cfg.UninstallForce)
		return
	}

	needsConfig := cmdRun.Used || cmdConfig.Used || cmdHost.Used ||
		cmdServiceStart.Used || cmdClusterStart.Used || cmdClusterJoin.Used

	if needsConfig && !configExists {
		if strings.TrimSpace(cfg.ConfigPath) != "" {
			logger.Fatal("config file not found at: ", cfg.ConfigPath)
		} else {
			ctx := installer.NewContext(logger)
			if ctx.Interactive {
				var doInit bool
				err := huh.NewConfirm().
					Title("Configuration Not Found").
					Description("No agbero.hcl found. Would you like to initialize one?").
					Value(&doInit).
					Run()
				if err == nil && doInit {
					path, err := helper.InitConfiguration(logger, "")
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
			if err := ch.Validate(resolvedPath); err != nil {
				logger.Fatal("invalid config: ", err)
			}
		case cmdConfigReload.Used:
			if err := ch.Reload(resolvedPath); err != nil {
				logger.Fatal("reload failed: ", err)
			}
			ui.New().SuccessLine("signal sent — check logs for reload status")
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
		Name:             woos.Name,
		DisplayName:      woos.Display,
		Description:      woos.Description,
		Arguments:        []string{"run", "-c", resolvedPath},
		WorkingDirectory: filepath.Dir(resolvedPath),
	}
	if cfg.DevMode {
		svcConfig.Arguments = append(svcConfig.Arguments, "--dev")
	}
	if runtime.GOOS == woos.Darwin && os.Geteuid() != 0 {
		cwd, _ := os.Getwd()
		if filepath.Dir(resolvedPath) == cwd {
			svcConfig.Name = "net.agbero.dev"
		} else {
			svcConfig.Name = "net.agbero"
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
			if cfg.UninstallAll {
				hel.Home().Uninstall(svc, resolvedPath, cfg.UninstallForce)
			} else {
				sh.Uninstall(svc)
			}
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

		u := ui.New()
		switch {
		case cmdClusterStart.Used:
			u.SectionHeader("Cluster — seed node")
			u.KeyValueBlock("", []ui.KV{
				{Label: "Config", Value: resolvedPath},
				{Label: "Mode", Value: "seed — this node is joinable"},
			})
		case cmdClusterJoin.Used:
			u.SectionHeader("Cluster — joining")
			u.KeyValueBlock("", []ui.KV{
				{Label: "Config", Value: resolvedPath},
				{Label: "Seed", Value: cfg.ClusterJoinIP},
			})
		default:
			u.SectionHeader("Starting")
			u.KeyValue("Config", resolvedPath)
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
	u := ui.New()
	u.Welcome(woos.Name, woos.Description, woos.Version, woos.Date, installer.BannerTmpl)
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

	u := ui.New()
	u.HelpScreen([]ui.HelpSection{
		{
			Title: "Scaffolding",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " init", Desc: "scaffold config in current folder"},
				{Cmd: prefix + exeName + " service install", Desc: "install config + system service"},
			},
		},
		{
			Title: "Execution",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " run", Desc: "run using discovered config"},
				{Cmd: exeName + " serve .", Desc: "serve current directory on the fly"},
				{Cmd: exeName + " serve . --markdown", Desc: "serve with .md files rendered as HTML"},
				{Cmd: exeName + " serve . --spa", Desc: "serve SPA (fallback to index.html on 404)"},
				{Cmd: exeName + " serve . --https", Desc: "serve with HTTPS"},
				{Cmd: exeName + " serve . --php", Desc: "serve with PHP"},
				{Cmd: exeName + " proxy :3000", Desc: "proxy local port 3000"},
			},
		},
		{
			Title: "Configuration",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " config validate", Desc: "validate config file"},
				{Cmd: exeName + " config view", Desc: "print config file"},
				{Cmd: exeName + " config edit", Desc: "edit config in $EDITOR"},
				{Cmd: exeName + " config path", Desc: "show config file path"},
				{Cmd: exeName + " config reload", Desc: "hot reload running instance"},
			},
		},
		{
			Title: "Certificates",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " cert install", Desc: "install local CA certificate"},
				{Cmd: exeName + " cert uninstall", Desc: "uninstall local CA certificate"},
				{Cmd: exeName + " cert list", Desc: "list managed certificates"},
				{Cmd: exeName + " cert info", Desc: "show certificate store information"},
			},
		},
		{
			Title: "Secrets & keys",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " secret cluster", Desc: "generate gossip secret key"},
				{Cmd: exeName + " secret key init", Desc: "generate internal auth key"},
				{Cmd: exeName + " secret token -s myapp", Desc: "generate API token for a service"},
				{Cmd: exeName + " secret hash -p mypass", Desc: "bcrypt hash a password"},
				{Cmd: exeName + " secret password", Desc: "generate random password + hash"},
			},
		},
		{
			Title: "Hosts",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " host list", Desc: "list configured hosts"},
				{Cmd: exeName + " host add", Desc: "add host/route (interactive)"},
				{Cmd: exeName + " host remove", Desc: "remove host/route (interactive)"},
			},
		},
		{
			Title: "System",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " system backup -o backup.zip -p mypass", Desc: "create encrypted backup"},
				{Cmd: exeName + " system restore -i backup.zip -p mypass", Desc: "restore from backup"},
			},
		},
		{
			Title: "Cluster",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " cluster start", Desc: "start as cluster seed node"},
				{Cmd: exeName + " cluster join <ip>", Desc: "join an existing cluster"},
			},
		},
		{
			Title: "Navigation",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " home", Desc: "print agbero home directory"},
				{Cmd: exeName + " home @", Desc: "open shell in home directory"},
				{Cmd: exeName + " home hosts @", Desc: "open shell in hosts.d"},
				{Cmd: exeName + " home .", Desc: "open home directory in file explorer"},
			},
		},
		{
			Title: "Service management",
			Commands: []ui.HelpCmd{
				{Cmd: prefix + exeName + " service install", Desc: "install system service"},
				{Cmd: prefix + exeName + " service start", Desc: "start service"},
				{Cmd: prefix + exeName + " service stop", Desc: "stop service"},
				{Cmd: prefix + exeName + " service restart", Desc: "restart service"},
				{Cmd: prefix + exeName + " service status", Desc: "check service status"},
				{Cmd: prefix + exeName + " service uninstall", Desc: "uninstall service"},
				{Cmd: prefix + exeName + " service uninstall --all", Desc: "remove everything agbero installed"},
				{Cmd: prefix + exeName + " uninstall", Desc: "alias — remove everything"},
			},
		},
	})
}
