package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agberohq/agbero/cmd/agbero/helper"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
	"github.com/integrii/flaggy"
	"github.com/kardianos/service"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
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

	cmdInstall := flaggy.NewSubcommand("install")
	cmdInstall.Description = "Scaffold configuration in current directory (alias for 'init')"

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

	cmdKeeper := flaggy.NewSubcommand("keeper")
	cmdKeeper.Description = "Manage the encrypted secret store"

	cmdKeeperList := flaggy.NewSubcommand("list")
	cmdKeeperList.Description = "List all keys in the keeper"

	cmdKeeperGet := flaggy.NewSubcommand("get")
	cmdKeeperGet.Description = "Retrieve a value from the keeper"
	cmdKeeperGet.AddPositionalValue(&cfg.KeeperKey, "key", 1, true, "Secret key name")

	cmdKeeperSet := flaggy.NewSubcommand("set")
	cmdKeeperSet.Description = "Store a value in the keeper"
	cmdKeeperSet.AddPositionalValue(&cfg.KeeperKey, "key", 1, true, "Secret key name")
	cmdKeeperSet.AddPositionalValue(&cfg.KeeperValue, "value", 2, false, "Plaintext value (omit to use --file)")
	cmdKeeperSet.Bool(&cfg.KeeperB64, "b", "b64", "Value is already base64-encoded — decode before storing")
	cmdKeeperSet.String(&cfg.KeeperFile, "f", "file", "Read value from file (e.g. a certificate)")

	cmdKeeperDelete := flaggy.NewSubcommand("delete")
	cmdKeeperDelete.Description = "Delete a key from the keeper"
	cmdKeeperDelete.AddPositionalValue(&cfg.KeeperKey, "key", 1, true, "Secret key name")
	cmdKeeperDelete.Bool(&cfg.KeeperForce, "f", "force", "Skip confirmation prompt")

	cmdKeeperRotate := flaggy.NewSubcommand("rotate")
	cmdKeeperRotate.Description = "Change the keeper master passphrase (re-encrypts all secrets)"

	cmdKeeperHelp := flaggy.NewSubcommand("help")
	cmdKeeperHelp.Description = "Show keeper command reference"

	cmdKeeper.AttachSubcommand(cmdKeeperList, 1)
	cmdKeeper.AttachSubcommand(cmdKeeperGet, 1)
	cmdKeeper.AttachSubcommand(cmdKeeperSet, 1)
	cmdKeeper.AttachSubcommand(cmdKeeperDelete, 1)
	cmdKeeper.AttachSubcommand(cmdKeeperRotate, 1)
	cmdKeeper.AttachSubcommand(cmdKeeperHelp, 1)

	cmdAdmin := flaggy.NewSubcommand("admin")
	cmdAdmin.Description = "Manage admin users and authentication"

	cmdAdminTOTP := flaggy.NewSubcommand("totp")
	cmdAdminTOTP.Description = "Manage TOTP two-factor authentication"

	cmdAdminTOTPSetup := flaggy.NewSubcommand("setup")
	cmdAdminTOTPSetup.Description = "Generate and store a new TOTP secret for an admin user"
	cmdAdminTOTPSetup.String(&cfg.KeeperUser, "u", "user", "Admin username")
	cmdAdminTOTPSetup.String(&cfg.KeeperOutFile, "o", "out", "Write QR code PNG to this file")

	cmdAdminTOTPQR := flaggy.NewSubcommand("qr")
	cmdAdminTOTPQR.Description = "Re-display the TOTP QR code for an admin user"
	cmdAdminTOTPQR.String(&cfg.KeeperUser, "u", "user", "Admin username")
	cmdAdminTOTPQR.String(&cfg.KeeperOutFile, "o", "out", "Write QR code PNG to this file")

	cmdAdminTOTP.AttachSubcommand(cmdAdminTOTPSetup, 1)
	cmdAdminTOTP.AttachSubcommand(cmdAdminTOTPQR, 1)
	cmdAdmin.AttachSubcommand(cmdAdminTOTP, 1)

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

	cmdCertDelete := flaggy.NewSubcommand("delete")
	cmdCertDelete.Description = "Delete a certificate for a domain from the store"
	cmdCertDelete.AddPositionalValue(&cfg.CertDomain, "domain", 1, true, "Domain name (e.g. admin.localhost)")

	cmdCert.AttachSubcommand(cmdCertInstall, 1)
	cmdCert.AttachSubcommand(cmdCertUninstall, 1)
	cmdCert.AttachSubcommand(cmdCertList, 1)
	cmdCert.AttachSubcommand(cmdCertInfo, 1)
	cmdCert.AttachSubcommand(cmdCertDelete, 1)

	cmdService := flaggy.NewSubcommand("service")
	cmdService.Description = "Manage the system service"

	cmdServiceInstall := flaggy.NewSubcommand("install")
	cmdServiceInstall.Description = "Install configuration and system service"
	cmdServiceInstall.Bool(&cfg.InstallHere, "", "here", "Install config in current directory only")

	cmdServiceUninstall := flaggy.NewSubcommand("uninstall")
	cmdServiceUninstall.Description = "Uninstall system service (use --all to remove everything)"
	cmdServiceUninstall.Bool(&cfg.UninstallAll, "", "all", "Remove service, CA, all data, and binary")
	cmdServiceUninstall.Bool(&cfg.UninstallForce, "", "force", "Skip confirmation and also remove the binary")

	cmdUninstall := flaggy.NewSubcommand("uninstall")
	cmdUninstall.Description = "Uninstall everything (service, CA, configurations, data, and binary)"
	cmdUninstall.Bool(&cfg.UninstallForce, "", "force", "Skip confirmation and also remove the binary")

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
	cmdSystemRestore.Bool(&cfg.SystemYes, "y", "yes", "Skip top-level confirmation prompt")

	cmdSystemUpdate := flaggy.NewSubcommand("update")
	cmdSystemUpdate.Description = "Download and apply the latest agbero release from GitHub"
	cmdSystemUpdate.Bool(&cfg.SystemForce, "f", "force", "Apply even if already on latest version")
	cmdSystemUpdate.Bool(&cfg.SystemYes, "y", "yes", "Skip confirmation prompt")

	cmdSystem.AttachSubcommand(cmdSystemBackup, 1)
	cmdSystem.AttachSubcommand(cmdSystemRestore, 1)
	cmdSystem.AttachSubcommand(cmdSystemUpdate, 1)

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
	flaggy.AttachSubcommand(cmdInstall, 1)
	flaggy.AttachSubcommand(cmdConfig, 1)
	flaggy.AttachSubcommand(cmdSecret, 1)
	flaggy.AttachSubcommand(cmdKeeper, 1)
	flaggy.AttachSubcommand(cmdAdmin, 1)
	flaggy.AttachSubcommand(cmdHost, 1)
	flaggy.AttachSubcommand(cmdCert, 1)
	flaggy.AttachSubcommand(cmdService, 1)
	flaggy.AttachSubcommand(cmdUninstall, 1)
	flaggy.AttachSubcommand(cmdSystem, 1)
	flaggy.AttachSubcommand(cmdRun, 1)
	flaggy.AttachSubcommand(cmdHome, 1)
	flaggy.AttachSubcommand(cmdServe, 1)
	flaggy.AttachSubcommand(cmdProxy, 1)
	flaggy.AttachSubcommand(cmdHelp, 1)

	flaggy.Parse()

	// store is opened later (after resolvedPath is known) for commands that
	// need it.  Commands that exit before the keeper block (serve, proxy,
	// system, secret, init) receive a nil store and must not call keeper ops.
	hel := helper.New(logger, shutdown, cfg, nil)

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
			hel.System().Restore(cfg.SystemIn, cfg.SystemPass, cfg.SystemForce, cfg.SystemYes)
			return
		}
		if cmdSystemUpdate.Used {
			hel.System().Update(cfg.SystemForce, cfg.SystemYes)
			return
		}
	}

	if cmdInit.Used || cmdInstall.Used {
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
			resolvedPath, configExists = helper.ResolveConfigPath(logger, "")
			if configExists {
				u := ui.New()
				u.InfoLine(fmt.Sprintf("using existing configuration: %s", resolvedPath))
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

	needsConfig := cmdRun.Used || cmdConfig.Used || cmdHost.Used || cmdServiceStart.Used || cmdKeeper.Used || cmdAdmin.Used
	if needsConfig && !configExists {
		if strings.TrimSpace(cfg.ConfigPath) != "" {
			logger.Fatal("config file not found at: ", cfg.ConfigPath)
		} else {
			ctx := setup.NewContext(logger)
			if ctx.Interactive {
				u := ui.New()
				doInit, err := u.ConfirmDefault(
					"Configuration Not Found",
					true,
					"No agbero.hcl found. Would you like to initialize one?",
				)
				if err == nil && doInit {
					path, err := helper.InitConfiguration(logger, "")
					if err != nil {
						logger.Fatal("init (config) failed: ", err)
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

	// Keeper lifecycle — single open for the whole process.
	//
	// Commands that need the keeper: run, keeper, admin.
	// All other commands have already returned above this point or do not
	// touch the store (config, cert, host, service control, cluster).
	//
	// Rules:
	//   run  → non-interactive, DisableAutoLock=true, fatal if still locked.
	//   CLI  → interactive (prompts user), AutoLock respected.

	cmdSecretNeedsKeeper := cmdSecret.Used && (cmdSecretKeyInit.Used || cmdSecretToken.Used)
	if cmdRun.Used || cmdKeeper.Used || cmdAdmin.Used || cmdSecretNeedsKeeper {
		global, globalErr := helper.LoadGlobal(resolvedPath)
		if globalErr != nil {
			logger.Fatal("failed to load config for keeper initialisation: ", globalErr)
		}

		// Recalibrate logger from config (file, level, format).
		logger, _ = zulu.Logging(&global.Logging, hel.Cfg.ServeMarkdown, shutdown)
		logger.Info("logger recalibrated")

		dataDir := global.Storage.DataDir
		ctx := setup.NewContext(logger)
		if !dataDir.IsSet() {
			dataDir = ctx.Paths.DataDir
		}

		// Interactive rules:
		//   keeper / admin CLI  → always interactive (operator is at the terminal)
		//   run + real terminal → interactive (developer running manually)
		//   run + no terminal   → non-interactive (service, CI, Docker)
		//   AGBERO_HEADLESS=1   → always non-interactive (setup.NewContext sets this)
		isInteractive := !cmdRun.Used || ctx.Interactive

		store, storeErr := secrets.Open(secrets.Config{
			DataDir:         dataDir,
			Setting:         &global.Security.Keeper,
			Logger:          logger,
			Interactive:     isInteractive,
			DisableAutoLock: cmdRun.Used, // server process must never auto-lock
		})
		if storeErr != nil {
			logger.Fatal("failed to open keeper: ", storeErr)
		}

		if cmdRun.Used && store.IsLocked() {
			store.Close()
			logger.Fatal("keeper is locked. Set AGBERO_PASSPHRASE environment variable, configure keeper.passphrase in agbero.hcl, or run interactively to be prompted")
		}

		// Register in both the keeper library's own global and agbero's secrets
		// hub so that all subsystems (expect resolver, TLS store, admin API) see
		// the same instance without further dependency injection.
		keeperlib.GlobalStore(store)
		secrets.SetGlobalStore(store)

		// NOTE: We do NOT register store.Close() with jack here.
		// jack.ShutdownConcurrent runs all handlers at the same time, which means
		// store.Close() would race with in-flight requests still holding BoltDB
		// transactions, causing a hang until the 10-second timeout fires.
		// Instead, store.Close() is called explicitly below after rr.Start()
		// returns — by that point all listeners have fully drained.

		// Re-construct hel with the live store injected.
		hel = helper.New(logger, shutdown, cfg, store)
	}

	if cmdSecret.Used {
		s := hel.Secret()
		switch {
		case cmdSecretCluster.Used:
			s.Cluster()
		case cmdSecretKey.Used && cmdSecretKeyInit.Used:
			s.KeyInit(resolvedPath)
		case cmdSecretToken.Used:
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

	if cmdKeeper.Used {
		k := hel.Keeper()
		switch {
		case cmdKeeperHelp.Used:
			flaggy.ShowHelpAndExit("keeper")
		case cmdKeeperList.Used:
			k.List(resolvedPath)
		case cmdKeeperGet.Used:
			k.Get(resolvedPath, cfg.KeeperKey)
		case cmdKeeperSet.Used:
			k.Set(resolvedPath, cfg.KeeperKey, cfg.KeeperValue, cfg.KeeperB64, cfg.KeeperFile)
		case cmdKeeperDelete.Used:
			k.Delete(resolvedPath, cfg.KeeperKey, cfg.KeeperForce)
		case cmdKeeperRotate.Used:
			k.Rotate(resolvedPath)
		default:
			k.REPL(resolvedPath)
		}
		return
	}

	if cmdAdmin.Used {
		a := hel.Admin()
		switch {
		case cmdAdminTOTP.Used && cmdAdminTOTPSetup.Used:
			a.TOTPSetup(resolvedPath, cfg.KeeperUser)
			if cfg.KeeperOutFile != "" {
				a.TOTPQRPNGFile(resolvedPath, cfg.KeeperUser, cfg.KeeperOutFile)
			}
		case cmdAdminTOTP.Used && cmdAdminTOTPQR.Used:
			a.TOTPQR(resolvedPath, cfg.KeeperUser)
			if cfg.KeeperOutFile != "" {
				a.TOTPQRPNGFile(resolvedPath, cfg.KeeperUser, cfg.KeeperOutFile)
			}
		default:
			flaggy.ShowHelpAndExit("admin")
		}
		return
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
		case cmdCertDelete.Used:
			ch.Delete(resolvedPath, cfg.CertDomain)
		default:
			flaggy.ShowHelpAndExit("cert")
		}
		return
	}

	if cmdService.Used {
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

		svc, _ := service.New(nil, svcConfig)
		sh := hel.Service()

		switch {
		case cmdServiceInstall.Used:
			sh.Install(svc, cfg.InstallHere, resolvedPath)
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

	if cmdRun.Used {
		rr := hel.Run()

		shutdown.Register(func() error {
			return nil
		})

		go func() {
			if err := rr.Start(resolvedPath, cfg.DevMode); err != nil {
				logger.Error("server error: ", err)
			}
			shutdown.TriggerShutdown()
		}()
	}

	if cmdHelp.Used {
		showHelpExamples()
		return
	}

	// Universal shutdown wait — all long-running commands fall through to here.
	stats := shutdown.Wait()

	if hel.Store != nil {
		keeperlib.GlobalClear()
		secrets.SetGlobalStore(nil)
		hel.Store.Close()
	}

	logger.Fields(
		"duration", stats.EndTime.Sub(stats.StartTime),
		"tasks_total", stats.TotalEvents,
		"tasks_failed", stats.FailedEvents,
	).Info("shutdown complete")
}

func welcome() {
	u := ui.New()
	u.Welcome(woos.Name, woos.Description, woos.Version, woos.Date, setup.BannerTmpl)
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
				{Cmd: exeName + " cert install --force", Desc: "force reinstall CA certificate"},
				{Cmd: exeName + " cert uninstall", Desc: "remove CA from system trust store"},
				{Cmd: exeName + " cert list", Desc: "list certificates in store"},
				{Cmd: exeName + " cert info", Desc: "show certificate details (backend, expiry, issuer)"},
				{Cmd: exeName + " cert delete admin.localhost", Desc: "delete a domain certificate from store"},
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
			Title: "Keeper (secret store)",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " keeper list", Desc: "list all keys in the encrypted store"},
				{Cmd: exeName + " keeper get <key>", Desc: "retrieve a secret value"},
				{Cmd: exeName + " keeper set <key> <value>", Desc: "store a plain string secret"},
				{Cmd: exeName + " keeper set <key> --file cert.pem", Desc: "store a certificate or binary file"},
				{Cmd: exeName + " keeper set <key> <b64> --b64", Desc: "store pre-encoded base64 value"},
				{Cmd: exeName + " keeper delete <key>", Desc: "delete a secret"},
				{Cmd: exeName + " keeper rotate", Desc: "change master passphrase (re-encrypts all)"},
			},
		},
		{
			Title: "Admin",
			Commands: []ui.HelpCmd{
				{Cmd: exeName + " admin totp setup -u alice", Desc: "generate TOTP secret + print QR"},
				{Cmd: exeName + " admin totp qr -u alice", Desc: "re-display TOTP QR for a user"},
				{Cmd: exeName + " admin totp qr -u alice -o qr.png", Desc: "write QR code to PNG file"},
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
				{Cmd: exeName + " system update", Desc: "update to latest release from GitHub"},
				{Cmd: exeName + " system update --force", Desc: "re-apply even if already on latest"},
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
				{Cmd: prefix + exeName + " service uninstall --all", Desc: "stop, uninstall CA, remove all data"},
				{Cmd: prefix + exeName + " service uninstall --all --force", Desc: "same + remove binary"},
				{Cmd: prefix + exeName + " uninstall", Desc: "confirm + remove everything (keeps binary)"},
				{Cmd: prefix + exeName + " uninstall --force", Desc: "skip confirm + remove everything including binary"},
			},
		},
	})
}
