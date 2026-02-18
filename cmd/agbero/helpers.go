package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/parser"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	tlss2 "git.imaxinacion.net/aibox/agbero/internal/pkg/tlss"
	"github.com/dustin/go-humanize"
	"github.com/integrii/flaggy"
	"golang.org/x/crypto/bcrypt"
)

// Embedded Assets
//
//go:embed data/agbero.hcl
var configTmpl string

//go:embed data/hosts.d/web.hcl
var tplWebHcl string

//go:embed data/hosts.d/admin.hcl
var tplAdminHcl string

//go:embed data/banner.txt
var bannerTmpl string

func welcome() {
	fmt.Println(bannerTmpl)
	fmt.Printf("\033[1;34m%s\033[0m - %s\n", woos.Name, woos.Description)
	fmt.Printf("\033[90mVersion: %s\033[0m\n\n", woos.Version)
}

func resolveConfigPath(flagPath string) (string, bool) {
	if strings.TrimSpace(flagPath) != "" {
		p := flagPath
		if abs, err := filepath.Abs(flagPath); err == nil {
			p = abs
		}
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
		return p, false
	}

	cwd, _ := os.Getwd()
	cwdPath := filepath.Join(cwd, woos.DefaultConfigName)
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, true
	}

	if userPaths, err := woos.GetUserDefaults(); err == nil {
		if _, err := os.Stat(userPaths.ConfigFile); err == nil {
			return userPaths.ConfigFile, true
		}
	}

	sysPaths := woos.DefaultPaths()
	if _, err := os.Stat(sysPaths.ConfigFile); err == nil {
		return sysPaths.ConfigFile, true
	}

	return "", false
}

func installConfiguration(here bool) (string, error) {
	var targetDir string

	if here {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		targetDir = cwd
	} else {
		sysPaths := woos.DefaultPaths()

		if os.Geteuid() == 0 {
			targetDir = sysPaths.BaseDir.Path()
		} else {
			userPaths, err := woos.GetUserDefaults()
			if err != nil {
				return "", err
			}
			targetDir = userPaths.BaseDir.Path()
		}
	}

	if err := os.MkdirAll(targetDir, woos.DirPerm); err != nil {
		return "", err
	}

	configFile := filepath.Join(targetDir, woos.DefaultConfigName)

	if _, err := os.Stat(configFile); err == nil {
		return "", fmt.Errorf("configuration already exists at %s", configFile)
	}

	// create subdirs
	for _, d := range []string{
		woos.HostDir.String(),
		woos.CertDir.String(),
		woos.DataDir.String(),
		woos.LogDir.String(),
	} {
		if err := os.MkdirAll(filepath.Join(targetDir, d), woos.DirPerm); err != nil {
			return "", err
		}
	}

	// write config
	content := strings.ReplaceAll(configTmpl, "{HOST_DIR}", woos.HostDir.String())
	content = strings.ReplaceAll(content, "{CERTS_DIR}", woos.CertDir.String())
	content = strings.ReplaceAll(content, "{DATA_DIR}", woos.DataDir.String())
	content = strings.ReplaceAll(content, "{LOGS_DIR}", woos.LogDir.String())

	secret, _ := generateSecureKey(128)
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)

	content = strings.ReplaceAll(content, "{ADMIN_PASSWORD}", string(hash))
	content = strings.ReplaceAll(content, "{ADMIN_SECRET}", secret)

	if err := os.WriteFile(configFile, []byte(content), woos.FilePermSecured); err != nil {
		return "", err
	}

	return configFile, nil
}

func reloadService(configFile string) error {
	if runtime.GOOS == woos.Windows {
		return fmt.Errorf("reload not supported via CLI on Windows, use Service Control")
	}

	global, err := loadConfig(configFile)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	if global.Storage.DataDir == "" {
		return fmt.Errorf("data_dir not configured")
	}

	pidFile := filepath.Join(global.Storage.DataDir, "agbero.pid")
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("could not read pid file %s: %w", pidFile, err)
	}

	pidStr := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid pid in file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("could not find process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to signal process %d: %w", pid, err)
	}

	return nil
}

func loadConfig(configFile string) (*alaye.Global, error) {
	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(configFile)
	woos.DefaultApply(global, abs)
	return global, nil
}

func validateConfig(configFile string) error {
	global, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHostFolder(hostsFolder, discovery.WithLogger(logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	logger.Fields("hosts_count", len(hosts), "hosts_dir", global.Storage.HostsDir).Info("configuration is valid")
	return nil
}

func listHosts(configFile string) error {
	global, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHostFolder(hostsFolder, discovery.WithLogger(logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		logger.Warn("no hosts found")
		return nil
	}
	for name, c := range hosts {
		logger.Fields(
			"host_id", name,
			"domains", c.Domains,
			"routes", len(c.Routes),
		).Info("configured host")
	}
	return nil
}

func handleServiceError(err error, cmd string, configPath string) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	exeName := getExecutableName()

	if runtime.GOOS == woos.Darwin && strings.Contains(errStr, "launchctl") {
		if strings.Contains(errStr, "Expecting a LaunchAgents path") {
			return fmt.Errorf("requires root: sudo %s service install", exeName)
		}
	}
	if runtime.GOOS == woos.Linux && strings.Contains(errStr, "systemctl") {
		return fmt.Errorf("requires root: sudo %s service %s", exeName, cmd)
	}
	return fmt.Errorf("failed to %s service: %v", cmd, err)
}

func getExecutableName() string {
	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}
	return woos.Name
}

func showHelpExamples(configPath string) {
	exeName := getExecutableName()
	fmt.Println("\n" + woos.Name + " - " + woos.Description + " v" + woos.Version)
	fmt.Println("\n===============================================================")
	fmt.Println("USAGE EXAMPLES")
	fmt.Println("===============================================================")
	fmt.Println("")
	fmt.Println("SCAFFOLDING:")
	fmt.Printf("  %s install --here   # Create config in current folder\n", exeName)
	fmt.Printf("  %s install          # Create config in system folder (requires root)\n", exeName)
	fmt.Println("")
	fmt.Println("EXECUTION:")
	fmt.Printf("  %s run              # Run using discovered config\n", exeName)
	fmt.Printf("  %s run --dev        # Run with debug logging\n", exeName)
	fmt.Printf("  %s reload           # Hot reload running instance\n", exeName)
	fmt.Println("")
	fmt.Println("SERVICE MANAGEMENT:")
	if runtime.GOOS == woos.Windows {
		fmt.Printf("  %s install\n", exeName)
		fmt.Printf("  %s start\n", exeName)
	} else {
		fmt.Printf("  sudo %s install\n", exeName)
		fmt.Printf("  sudo %s start\n", exeName)
	}
}

func showCertInfo(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Warnf("Could not load config: %v", err)
		return
	}
	storageDir := woos.NewFolder(global.Storage.CertsDir)
	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Printf("Storage Listing: %s\n", storageDir.Path())
	if !storageDir.Exists("") {
		fmt.Println("⚠  Listing does not exist")
		return
	}
	files, err := storageDir.ReadFiles()
	if err != nil {
		fmt.Printf("⚠  Cannot read directory: %v\n", err)
		return
	}
	count := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pem") {
			count++
			info, _ := file.Info()
			fmt.Printf("  • %s (%s, %s)\n",
				file.Name(),
				humanize.Bytes(uint64(info.Size())),
				info.ModTime().Format("2006-01-02"))
		}
	}
	if count == 0 {
		fmt.Println("  (Unknown certificates found)")
	}
}

func handleCertCommands(install, uninstall, list, info bool) {
	installer := tlss2.NewInstaller(logger)
	if install {
		global, err := loadConfig(configPath)
		if err == nil && global.Storage.CertsDir != "" {
			_ = installer.SetStorageDir(woos.NewFolder(global.Storage.CertsDir))
		}
		certDir := installer.CertDir.Path()
		if tlss2.IsCARootInstalled(certDir) && !forceCAInstall {
			logger.Info("CA root certificate is already installed. Use --force to reinstall.")
			return
		}
		logger.Info("Installing CA root certificate...")
		if err := installer.InstallCARootIfNeeded(); err != nil {
			logger.Fatal("Failed to install CA: ", err)
		}
		logger.Info("CA root installed. Browsers should now trust localhost certificates.")
		return
	}
	if uninstall {
		logger.Info("Uninstalling CA root certificate...")
		if err := installer.UninstallCARoot(); err != nil {
			logger.Fatal("Failed to uninstall CA: ", err)
		}
		logger.Info("CA root uninstalled from system trust store.")
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

func handleGossipCommands(init, token, secret, status bool) {
	if init {
		handleGossipInit(configPath)
		return
	}
	if token {
		handleGossipToken(configPath)
		return
	}
	if secret {
		handleGossipSecret()
		return
	}
	if status {
		handleGossipStatus(configPath)
		return
	}
	showGossipHelp()
}

func handleGossipInit(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}
	certsDir := woos.NewFolder(global.Storage.CertsDir)
	keyPath := filepath.Join(certsDir.Path(), "gossip.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logger.Info("Generating gossip private key...")
		if err := security.GenerateNewKeyFile(keyPath); err != nil {
			logger.Fatal("Failed to generate key: ", err)
		}
		_ = os.Chmod(keyPath, 0600)
		logger.Info("Generated gossip key: ", keyPath)
	} else {
		logger.Info("Gossip key already exists: ", keyPath)
	}
	fmt.Println("\n[ACTION REQUIRED] Gossip configuration guide:")
	fmt.Println("===========================================")
	fmt.Printf("1. Private key location: %s\n", keyPath)
	fmt.Println("2. You MUST add this block to your agbero.hcl to enable gossip:")
	fmt.Printf(`
gossip {
  enabled = true
  port    = 7946
  private_key_file = "%s"
  # seeds = ["node2:7946"]
}`, keyPath)
	fmt.Println("\n===========================================")
}

func handleGossipToken(configPath string) {
	if gossipService == "" {
		logger.Fatal("Error: --service flag is required for gossip token")
	}
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}
	if global.Gossip.Enabled.NotActive() || global.Gossip.PrivateKeyFile == "" {
		logger.Fatal("Gossip is disabled in config. Run 'agbero gossip init' AND update your config file.")
	}
	tm, err := security.LoadKeys(global.Gossip.PrivateKeyFile)
	if err != nil {
		logger.Fatal("Error loading gossip key: ", err)
	}
	if gossipTTL == 0 {
		gossipTTL = 720 * time.Hour
	}
	token, err := tm.Mint(gossipService, gossipTTL)
	if err != nil {
		logger.Fatal("Error generating token: ", err)
	}
	fmt.Printf("\nGossip token for service: %s\n", gossipService)
	fmt.Printf("TTL: %s\n", gossipTTL)
	fmt.Println(token)
}

func handleGossipSecret() {
	// Generate 32 bytes (256 bits)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		logger.Fatal("Random generation failed: ", err)
	}

	// We use StdEncoding because the config parser (alaye/value.go) uses base64.StdEncoding.DecodeString
	encoded := base64.StdEncoding.EncodeToString(key)

	fmt.Println("\nGenerated 32-byte Secret Key (AES-256 compatible):")
	fmt.Println("==================================================")
	fmt.Printf("b64.%s\n", encoded)
	fmt.Println("==================================================")
	fmt.Println("\nUsage in agbero.hcl:")
	fmt.Println("gossip {")
	fmt.Printf("  secret_key = \"b64.%s\"\n", encoded)
	fmt.Println("}")
}

func handleGossipStatus(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}
	fmt.Println("\nGossip Configuration Active")
	fmt.Println("===========================")
	if !global.Gossip.Enabled.Active() {
		fmt.Println("Active: DISABLED")
		return
	}
	fmt.Println("Active: ENABLED")
	fmt.Printf("Port: %d\n", global.Gossip.Port)

	if global.Gossip.PrivateKeyFile != "" {
		if _, err := os.Stat(global.Gossip.PrivateKeyFile); err == nil {
			fmt.Printf("Private key: %s (exists)\n", global.Gossip.PrivateKeyFile)
			if _, err := security.LoadKeys(global.Gossip.PrivateKeyFile); err == nil {
				fmt.Println("Key status: VALID")
			} else {
				fmt.Printf("Key status: INVALID (%v)\n", err)
			}
		} else {
			fmt.Printf("Private key: %s (NOT FOUND)\n", global.Gossip.PrivateKeyFile)
		}
	} else {
		fmt.Println("Private key: NOT CONFIGURED")
	}

	if len(global.Gossip.Seeds) > 0 {
		fmt.Printf("Cluster seeds: %v\n", global.Gossip.Seeds)
	} else {
		fmt.Println("Cluster seeds: none (standalone mode)")
	}

	if global.Gossip.SecretKey != "" {
		fmt.Println("Encryption: ENABLED")
	} else {
		fmt.Println("Encryption: DISABLED (Warning: Cluster traffic is unencrypted)")
	}
}

func showGossipHelp() {
	exeName := getExecutableName()
	fmt.Printf("\n%s gossip - Manage gossip cluster configuration\n", exeName)
	fmt.Println("================================================")
	fmt.Println("Commands:")
	fmt.Printf("  %s gossip init              Generate gossip key\n", exeName)
	fmt.Printf("  %s gossip secret            Generate encryption secret\n", exeName)
	fmt.Printf("  %s gossip token --service X Generate auth token\n", exeName)
	fmt.Printf("  %s gossip status            Show status\n", exeName)
}

func generateSecureKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(b)
	return encoded, nil
}
