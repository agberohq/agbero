package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/security"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/dustin/go-humanize"
)

// Embedded Assets
//
//go:embed data/agbero.hcl
var configTmpl string

//go:embed data/sample.hcl
var hostSampleTmpl string

//go:embed data/banner.txt
var bannerTmpl string

func welcome() {
	fmt.Print(bannerTmpl)
	fmt.Println(woos.Name + " - " + woos.Description)
	fmt.Println("Version: " + woos.Version + "")
}

// resolveConfigPath implements the search order
func resolveConfigPath(flagPath string) (string, bool) {
	// 1) Explicit Flag
	if strings.TrimSpace(flagPath) != "" {
		p := flagPath
		if abs, err := filepath.Abs(flagPath); err == nil {
			p = abs
		}
		_, err := os.Stat(p)
		return p, err == nil
	}

	// 2) CWD
	cwd, _ := os.Getwd()
	cwdPath := filepath.Join(cwd, woos.DefaultConfigName)
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, true
	}

	// 3) User Config
	if userPaths, err := woos.GetUserDefaults(); err == nil {
		if _, err := os.Stat(userPaths.ConfigFile); err == nil {
			return userPaths.ConfigFile, true
		}
	}

	// 4) System Config
	sysPaths := woos.DefaultPaths()
	if _, err := os.Stat(sysPaths.ConfigFile); err == nil {
		return sysPaths.ConfigFile, true
	}

	// Default fallback: CWD path (may not exist)
	return cwdPath, false
}

func ensureConfig(configFile string) error {
	if configFile == "" {
		return fmt.Errorf("config path is empty")
	}

	if _, err := os.Stat(configFile); err == nil {
		return ensureLayoutForConfig(configFile)
	}

	logger.Fields("path", configFile).Info("config not found, generating default")

	if err := os.MkdirAll(filepath.Dir(configFile), woos.DirPerm); err != nil {
		return fmt.Errorf("mkdir config parent: %w", err)
	}

	content := strings.ReplaceAll(configTmpl, "{HOST_DIR}", woos.HostDir.String())
	content = strings.ReplaceAll(content, "{CERTS_DIR}", woos.CertDir.String())
	content = strings.ReplaceAll(content, "{DATA_DIR}", woos.DataDir.String())

	if err := os.WriteFile(configFile, []byte(content), woos.FilePerm); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}

	if err := ensureLayoutForConfig(configFile); err != nil {
		return err
	}

	logger.Fields("file", configFile).Info("default configuration created")
	return nil
}

func ensureLayoutForConfig(configFile string) error {
	base := woos.NewFolder(filepath.Dir(configFile))

	hostsDir := base.Join(woos.HostDir.String())
	certsDir := base.Join(woos.CertDir.String())
	dataDir := base.Join(woos.DataDir.String())

	if err := hostsDir.Ensure("", false); err != nil {
		return fmt.Errorf("ensure hosts dir: %w", err)
	}
	if err := certsDir.Ensure("", true); err != nil {
		return fmt.Errorf("ensure certs dir: %w", err)
	}
	if err := dataDir.Ensure("", false); err != nil {
		return fmt.Errorf("ensure data dir: %w", err)
	}

	if empty, err := hostsDir.IsEmpty(); err == nil && empty {
		samplePath := filepath.Join(hostsDir.Path(), "localhost.hcl")
		_ = os.WriteFile(samplePath, []byte(hostSampleTmpl), woos.FilePerm)
	}

	return nil
}

func loadConfig(configFile string) (*alaye.Global, error) {
	global, err := core.LoadGlobal(configFile)
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

func getExecutableName() string {
	if len(os.Args) > 0 {
		base := filepath.Base(os.Args[0])
		if strings.Contains(base, "go-build") || base == "helpers" {
			return woos.Name
		}
		return base
	}
	return woos.Name
}

func handleServiceError(err error, cmd string, configPath string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	exeName := getExecutableName()

	if runtime.GOOS == woos.Darwin && strings.Contains(errStr, "launchctl") {
		if strings.Contains(errStr, "Expecting a LaunchAgents path") {
			return fmt.Errorf(`%s

AGBERO SERVICE HELP (macOS)
===============================================================
You are trying to install a system service without root privileges.

FIXES:
1. Run as root: sudo %s install --config "%s"
2. Run as user: Choose "User" install mode or run without sudo.
`, err, exeName, configPath)
		}

		if strings.Contains(errStr, "Load failed: 5") {
			return fmt.Errorf(`%s

AGBERO SERVICE HELP (macOS)
===============================================================
Service load failed. Usually permission or file issues.

FIXES:
1. Unload existing: sudo launchctl unload /Library/LaunchDaemons/agbero.plist
2. Reinstall with sudo: sudo %s install --config "%s"
`, err, exeName, configPath)
		}
	}

	if runtime.GOOS == "linux" && strings.Contains(errStr, "systemctl") {
		return fmt.Errorf(`%s

AGBERO SERVICE HELP (Linux)
===============================================================
Systemd operation failed. Ensure you are using sudo.

FIXES:
1. Run with sudo: sudo %s %s --config "%s"
2. Check logs: sudo journalctl -u agbero -f
`, err, exeName, cmd, configPath)
	}

	return fmt.Errorf(`%s

AGBERO SERVICE ERROR
===============================================================
Failed to %s service.

FIXES:
1. Try running with sudo/Administrator privileges.
2. Check if the config file exists at "%s".
3. Use interactive mode: %s run --config "%s"
`, err, cmd, configPath, exeName, configPath)
}

func showHelpExamples(configPath string) {
	exeName := getExecutableName()

	fmt.Println("\n" + woos.Name + " - " + woos.Description + " v" + woos.Version)
	fmt.Println("\n===============================================================")
	fmt.Println("USAGE EXAMPLES")
	fmt.Println("===============================================================")
	fmt.Println("")
	fmt.Println("DEVELOPMENT / TESTING:")
	fmt.Printf("  %s run --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s run --dev --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s run --dev --gossip --config \"%s\"\n", exeName, configPath)
	fmt.Println("")
	fmt.Println("CONFIGURATION:")
	fmt.Printf("  %s validate --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s hosts --config \"%s\"\n", exeName, configPath)
	fmt.Println("")
	fmt.Println("GOSSIP CLUSTER:")
	fmt.Printf("  %s gossip init --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s gossip token --service myservice --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s gossip status --config \"%s\"\n", exeName, configPath)
	fmt.Println("")

	if runtime.GOOS == woos.Darwin {
		fmt.Println("macOS SERVICE:")
		fmt.Printf("  sudo %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  sudo %s start --config \"%s\"\n", exeName, configPath)
	} else if runtime.GOOS == "linux" {
		fmt.Println("LINUX SERVICE:")
		fmt.Printf("  sudo %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  sudo %s start --config \"%s\"\n", exeName, configPath)
	} else if runtime.GOOS == "windows" {
		fmt.Println("WINDOWS SERVICE:")
		fmt.Printf("  %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  %s start --config \"%s\"\n", exeName, configPath)
	}

	fmt.Println("\n===============================================================")
	fmt.Println("For more options, use: " + exeName + " --help")
	fmt.Println("===============================================================")
}

func showCertInfo(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Warnf("Could not load config: %v", err)
		return
	}

	storageDir := woos.NewFolder(global.Storage.CertsDir)

	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Println("===============================================================")
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
		fmt.Println("  (No certificates found)")
	}
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

	fmt.Println("\nGossip configuration guide:")
	fmt.Println("==========================")
	fmt.Printf("Private key: %s\n", keyPath)
	fmt.Println("\nAdd to your agbero.hcl config:")
	fmt.Printf(`
gossip {
  enabled = true
  port    = 7946
  private_key_file = "%s"
  # Optional: seeds = ["node2:7946", "node3:7946"]
}`, keyPath)
	fmt.Println()
}

func handleGossipToken(configPath string) {
	if gossipService == "" {
		logger.Fatal("Error: --service flag is required for gossip token")
	}

	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}

	if !global.Gossip.Enabled || global.Gossip.PrivateKeyFile == "" {
		logger.Fatal("Gossip not configured or key file missing in config. Run 'agbero gossip init' first.")
	}

	keyPath := global.Gossip.PrivateKeyFile
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logger.Fatalf("Gossip key not found: %s\nRun 'agbero gossip init' to generate it.", keyPath)
	}

	tm, err := security.LoadKeys(keyPath)
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
	fmt.Println("--------------------------")
	fmt.Println(token)
	fmt.Println("--------------------------")

	fmt.Printf("\nUse in your service metadata:\n")
	fmt.Printf(`{"token":"%s","port":PORT,"host":"%s.example.com","path":"/"}`, token, gossipService)
	fmt.Println()
}

func handleGossipStatus(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}

	fmt.Println("\nGossip Configuration Status")
	fmt.Println("===========================")

	if !global.Gossip.Enabled {
		fmt.Println("Status: DISABLED")
		fmt.Println("\nTo enable: agbero gossip init")
		return
	}

	fmt.Println("Status: ENABLED")
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
	}
}

func showGossipHelp() {
	exeName := getExecutableName()
	fmt.Printf("\n%s gossip - Manage gossip cluster configuration\n", exeName)
	fmt.Println("================================================")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Printf("  %s gossip init              Generate gossip key and show configuration\n", exeName)
	fmt.Printf("  %s gossip token --service NAME  Generate token for a service\n", exeName)
	fmt.Printf("  %s gossip status            Show current gossip configuration\n", exeName)
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s gossip init\n", exeName)
	fmt.Printf("  %s gossip token --service api --ttl 168h\n", exeName)
	fmt.Printf("  %s gossip status\n", exeName)
	fmt.Println()
}
