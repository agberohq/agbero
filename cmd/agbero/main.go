package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
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

	// Certificate Management Flags
	forceCAInstall bool
	caMethod       string
	certDir        string
)

func main() {
	// Setup Flaggy
	flaggy.SetName(woos.Name)
	flaggy.SetDescription(woos.Description)
	flaggy.SetVersion(version) // Handles --version automatically

	// Global flags - No default value set here to detect if user provided it
	flaggy.String(&configPath, "c", "config", "Path to configuration file")
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

	// --- Certificate Management Subcommands ---
	cmdCert := flaggy.NewSubcommand("cert")
	cmdCert.Description = "Manage local certificates for development"

	cmdInstallCA := flaggy.NewSubcommand("install-ca")
	cmdInstallCA.Description = "Install local CA certificate for development (if not already installed)"
	cmdInstallCA.Bool(&forceCAInstall, "f", "force", "Force reinstall even if CA already installed")
	cmdInstallCA.String(&caMethod, "m", "method", "Method to use: auto|mkcert|truststore (default: auto)")

	cmdListCerts := flaggy.NewSubcommand("list")
	cmdListCerts.Description = "List available certificates"

	cmdCertInfo := flaggy.NewSubcommand("info")
	cmdCertInfo.Description = "Show certificate information and storage location"
	cmdCertInfo.String(&certDir, "d", "dir", "Certificate directory to inspect (default: from config)")

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

	// Certificate commands
	cmdCert.AttachSubcommand(cmdInstallCA, 1)
	cmdCert.AttachSubcommand(cmdListCerts, 1)
	cmdCert.AttachSubcommand(cmdCertInfo, 1)
	flaggy.AttachSubcommand(cmdCert, 1)

	// Key commands
	cmdKey.AttachSubcommand(cmdKeyGen, 1)
	cmdKey.AttachSubcommand(cmdKeyInit, 1)
	flaggy.AttachSubcommand(cmdKey, 1)

	flaggy.Parse()
	welcome()

	// --- Smart Config Resolution ---
	// 1. Resolve the path
	resolvedPath, exists := resolveConfigPath(configPath)

	// 2. Fail if user explicitly asked for a specific path that doesn't exist
	if configPath != "" && !exists {
		// Log error via minimal logger since global logger isn't set up yet
		fmt.Printf("Error: Config file not found: %s\n", configPath)
		os.Exit(1)
	}

	// 3. Update the global variable to the resolved path
	configPath = resolvedPath

	// Handle Help
	if cmdHelp.Used {
		showHelpExamples(configPath)
		return
	}

	// --- Handle Certificate Commands (Exit early) ---
	if cmdCert.Used {
		if cmdInstallCA.Used {
			handleInstallCA()
			return
		}

		if cmdListCerts.Used {
			handleListCerts()
			return
		}

		if cmdCertInfo.Used {
			handleCertInfo()
			return
		}

		flaggy.ShowHelpAndExit("cert")
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
		// 1. Auto-Generate Config if missing
		if err := ensureConfig(configPath); err != nil {
			logger.Fatal("Failed to generate configuration: ", err)
		}

		// 2. Load Config to check for HTTPS
		global, err := loadConfig(configPath)
		if err != nil {
			logger.Fatal("Failed to load config: ", err)
		}

		// 3. Auto-Install CA if needed
		checkAndInstallCA(global)

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

// checkAndInstallCA checks if HTTPS is enabled and installs CA root if missing
func checkAndInstallCA(global *alaye.Global) {
	hasHTTPS := len(global.Bind.HTTPS) > 0

	// If no HTTPS configured, skip
	if !hasHTTPS {
		return
	}

	// Setup minimal logger for this check
	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(false))
	minimalLogger := ll.New("agbero-cert", ll.WithHandler(loggerTerminal)).Enable()

	installer := tlss.NewCertInstaller(minimalLogger)

	if !installer.IsCARootInstalled() {
		logger.Info("HTTPS enabled but CA root not found. Auto-installing...")

		// Attempt auto-install
		if err := installer.InstallCARootIfNeeded(); err != nil {
			logger.Warn("Failed to auto-install CA root: %v", err)
			logger.Warn("You may need to run 'agbero cert install-ca' manually or trust the certificate in your browser.")
		} else {
			logger.Info("CA root installed successfully.")
		}
	}
}

func handleInstallCA() {
	// Setup minimal logger for certificate operations
	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(false))
	minimalLogger := ll.New("agbero-cert", ll.WithHandler(loggerTerminal)).Enable()

	installer := tlss.NewCertInstaller(minimalLogger)

	if installer.IsCARootInstalled() && !forceCAInstall {
		fmt.Println("CA root certificate is already installed in system trust store")
		fmt.Println("Use --force to reinstall if needed")
		return
	}

	fmt.Println("Installing CA root certificate...")

	// Determine installation method
	switch caMethod {
	case "mkcert":
		fmt.Println("Using mkcert method...")
		if err := installer.InstallWithMkcert(); err != nil {
			fmt.Printf("Failed to install CA with mkcert: %v\n", err)
			os.Exit(1)
		}
	case "truststore":
		fmt.Println("Using truststore method...")
		if err := installer.InstallWithTruststore(); err != nil {
			fmt.Printf("Failed to install CA with truststore: %v\n", err)
			os.Exit(1)
		}
	default: // "auto"
		fmt.Println("Auto-detecting best method...")
		if err := installer.InstallCARootIfNeeded(); err != nil {
			fmt.Printf("Failed to install CA: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("CA certificate installed successfully")

	// Test the installation
	if installer.TestCAInstallation() {
		fmt.Println("CA installation verified")
	} else {
		fmt.Println("WARNING: CA installed but verification failed. You may need to restart your browser.")
	}

	// Show next steps
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Restart your browser if it was open during installation")
	fmt.Println("  2. Use 'agbero cert info' to see certificate storage location")
	fmt.Println("  3. Configure hosts with 'tls { mode = \"auto\" }' for automatic local certificates")
}

func handleListCerts() {
	// Setup minimal logger for certificate operations
	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(false))
	minimalLogger := ll.New("agbero-cert", ll.WithHandler(loggerTerminal)).Enable()

	installer := tlss.NewCertInstaller(minimalLogger)

	// Try to load config to get tls_storage_dir
	global, err := loadConfig(configPath)
	if err == nil && global.TLSStorageDir != "" {
		if err := installer.SetStorageDir(global.TLSStorageDir); err != nil {
			fmt.Printf("WARNING: Failed to set storage dir from config: %v\n", err)
		}
	}

	certs, err := installer.ListCertificates()
	if err != nil {
		fmt.Printf("Failed to list certificates: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate directory: %s\n", installer.CertDir)

	if len(certs) == 0 {
		fmt.Println("No certificates found")
		return
	}

	fmt.Printf("Found %d certificate(s):\n", len(certs))
	for i, cert := range certs {
		fmt.Printf("  %d. %s\n", i+1, cert)
	}

	fmt.Println("\nTo use these certificates in your config:")
	fmt.Println(`  tls {
    mode = "local"
    local {
      cert_file = "` + filepath.Join(installer.CertDir, "localhost.pem") + `"
      key_file  = "` + filepath.Join(installer.CertDir, "localhost.key.pem") + `"
    }
  }`)
}

func handleCertInfo() {
	// Setup minimal logger
	loggerTerminal := lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(false))
	minimalLogger := ll.New("agbero-cert", ll.WithHandler(loggerTerminal)).Enable()

	installer := tlss.NewCertInstaller(minimalLogger)

	// Override directory if specified
	if certDir != "" {
		if err := installer.SetStorageDir(certDir); err != nil {
			fmt.Printf("Failed to set certificate directory: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Println("==========================================")

	// Check CA installation
	if installer.IsCARootInstalled() {
		fmt.Println("✓ CA root certificate is installed in system trust store")
	} else {
		fmt.Println("✗ CA root certificate is NOT installed")
		fmt.Println("  Run: agbero cert install-ca")
	}

	// Show storage directory
	fmt.Printf("\nStorage Directory: %s\n", installer.CertDir)

	// Check if directory exists
	if _, err := os.Stat(installer.CertDir); os.IsNotExist(err) {
		fmt.Println("WARNING: Directory does not exist")
	} else {
		// List certificates
		files, err := os.ReadDir(installer.CertDir)
		if err != nil {
			fmt.Printf("WARNING: Cannot read directory: %v\n", err)
		} else {
			certCount := 0
			var totalSize int64
			for _, file := range files {
				if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pem") ||
					strings.HasSuffix(file.Name(), ".crt") ||
					strings.HasSuffix(file.Name(), ".key")) {
					certCount++
					if info, err := file.Info(); err == nil {
						totalSize += info.Size()
					}
				}
			}

			fmt.Printf("Found %d certificate file(s) (%.2f MB total)\n", certCount,
				float64(totalSize)/(1024*1024))

			if certCount > 0 {
				fmt.Println("\nAvailable certificates:")
				for _, file := range files {
					if !file.IsDir() && (strings.HasSuffix(file.Name(), ".pem") ||
						strings.HasSuffix(file.Name(), ".crt")) {
						fullPath := filepath.Join(installer.CertDir, file.Name())
						info, err := os.Stat(fullPath)
						if err == nil {
							// Format size
							size := info.Size()
							var sizeStr string
							if size < 1024 {
								sizeStr = fmt.Sprintf("%d B", size)
							} else if size < 1024*1024 {
								sizeStr = fmt.Sprintf("%.1f KB", float64(size)/1024)
							} else {
								sizeStr = fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
							}

							fmt.Printf("  • %s (%s, modified %s)\n",
								file.Name(),
								sizeStr,
								info.ModTime().Format("2006-01-02"))
						}
					}
				}
			}
		}
	}

	// Show mkcert availability
	if installer.IsMkcertInstalled() {
		fmt.Println("\n✓ mkcert is available on system")
	} else {
		fmt.Println("\n✗ mkcert is not installed")
		fmt.Println("  Will download temporarily when needed")
	}

	fmt.Println("\nUsage examples:")
	fmt.Println(`  1. For automatic local certificates:`)
	fmt.Println(`     tls {
       mode = "auto"
     }`)
	fmt.Println()
	fmt.Println(`  2. For existing certificates:`)
	fmt.Println(`     tls {
       mode = "local"
       local {
         cert_file = "` + filepath.Join(installer.CertDir, "localhost.pem") + `"` + "\n")
	fmt.Println(`         key_file  = "` + filepath.Join(installer.CertDir, "localhost.key.pem") + `"`)
	fmt.Println(`       }
     }`)
}
