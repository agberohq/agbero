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

// resolveConfigPath implements the search order:
// resolveConfigPath implements the search order:
func resolveConfigPath(flagPath string) (string, bool) {
	// 1. Explicit Flag
	if flagPath != "" {
		if _, err := os.Stat(flagPath); err == nil {
			return flagPath, true
		}
		return flagPath, false
	}

	// 2. CWD
	cwd, _ := os.Getwd()
	cwdPath := filepath.Join(cwd, woos.DefaultConfigName)
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, true
	}

	// 3. User Config
	if userPaths, err := woos.GetUserDefaults(); err == nil {
		if _, err := os.Stat(userPaths.ConfigFile); err == nil {
			return userPaths.ConfigFile, true
		}
	}

	// 4. System Config
	sysPaths := woos.DefaultPaths()
	if _, err := os.Stat(sysPaths.ConfigFile); err == nil {
		return sysPaths.ConfigFile, true
	}

	return cwdPath, false
}

// ensureConfig checks if config exists, if not, generates a default one using embedded templates.
func ensureConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	logger.Fields("path", path).Info("config not found, generating default")

	// Create Base Directory
	baseDir := woos.NewFolder(filepath.Dir(path))
	if err := baseDir.Ensure(woos.Folder(""), false); err != nil {
		return fmt.Errorf("ensure base dir: %w", err)
	}

	// 1. Write Main Config
	// Inject hosts_dir into the template (using string representation of Folder constant)
	content := strings.ReplaceAll(configTmpl, "{HOST_DIR}", woos.HostDir.String())

	//ll.Dump(content)
	if err := os.WriteFile(path, []byte(content), woos.FilePerm); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}

	// 2. Create Hosts Directory
	// We assume relative to config file for dev mode usually
	hostsDir := baseDir.Join(woos.HostDir.Name())

	if err := hostsDir.Ensure("", false); err != nil {
		logger.Warnf("failed to create hosts directory: %v", err)
	} else {
		// Write Sample Host
		samplePath := filepath.Join(hostsDir.Path(), "localhost.hcl")
		_ = os.WriteFile(samplePath, []byte(hostSampleTmpl), woos.FilePerm)
	}

	// 3. Create Certs Directory (Secure)
	certsDir := baseDir.Join(woos.CertDir.Name())
	if err := certsDir.Ensure("", true); err != nil { // true = SecurePerm (0700)
		logger.Warnf("failed to create certs directory: %v", err)
	}

	logger.Fields("file", path).Info("default configuration created")
	return nil
}

// loadConfig parses the config and ensures hosts_dir is absolute.
func loadConfig(path string) (*alaye.Global, error) {
	// Parse using Core
	global, err := core.LoadGlobal(path)
	if err != nil {
		return nil, err
	}

	// Apply Defaults (Includes Path resolution logic)
	// We rely on woos.DefaultApply to handle the Folder/Path logic
	// passing the absolute path of the config file to resolve relative paths against it.
	absConfigPath, _ := filepath.Abs(path)
	woos.DefaultApply(global, absConfigPath)

	return global, nil
}

// Update the signature to accept paths
func installDefaults(configFile, hostsDir string) error {
	// 1. Create Hosts Directory
	// We use woos.NewFolder to handle the creation logic cleanly
	hDir := woos.NewFolder(hostsDir)

	logger.Fields("dir", hostsDir).Info("creating configuration directory")
	if err := hDir.Ensure("", false); err != nil {
		return fmt.Errorf("mkdir hosts: %w", err)
	}

	// 2. Check/Create Config File
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		logger.Fields("file", configFile).Info("writing default config")

		// Calculate relative path for template if possible, otherwise use absolute
		// For the template, we want the hosts_dir string to be injected
		content := strings.ReplaceAll(configTmpl, "{HOST_DIR}", hostsDir)

		// Create parent dir for config file if it doesn't exist
		configDir := filepath.Dir(configFile)
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("mkdir config parent: %w", err)
		}

		if err := os.WriteFile(configFile, []byte(content), woos.FilePerm); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}
	return nil
}

func validateConfig(path string) error {
	global, err := loadConfig(path)
	if err != nil {
		return err
	}

	// Use Folder type from Config
	hostsFolder := woos.MakeFolder(global.Storage.HostsDir, woos.HostDir)

	hm := discovery.NewHostFolder(hostsFolder, discovery.WithLogger(logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	logger.Fields("hosts_count", len(hosts), "hosts_dir", global.Storage.HostsDir).Info("configuration is valid")
	return nil
}

func listHosts(path string) error {
	global, err := loadConfig(path)
	if err != nil {
		return err
	}

	hostsFolder := woos.MakeFolder(global.Storage.HostsDir, woos.HostDir)
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

func welcome() {
	fmt.Print(bannerTmpl)
	fmt.Println("\n" + woos.Name + " - " + woos.Description + " v" + woos.Version)
}

func getExecutableName() string {
	if len(os.Args) > 0 {
		base := filepath.Base(os.Args[0])
		if strings.Contains(base, "go-build") || base == "helpers" {
			return "agbero"
		}
		return base
	}
	return "agbero"
}

func handleServiceError(err error, cmd string, configPath string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	exeName := getExecutableName()

	// macOS specific guidance
	if runtime.GOOS == woos.Darwin && strings.Contains(errStr, "launchctl") {
		if strings.Contains(errStr, "Expecting a LaunchAgents path") {
			return fmt.Errorf(`%s

AGBERO SERVICE HELP (macOS)
===============================================================
You are trying to install a system service without root privileges.

FIXES:
1. Run as root: sudo %s install --config "%s"
2. Run as user: Check if service configuration is set to User mode.
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

	// Linux systemd guidance
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

	// Generic fallback
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

	// Resolve cert folder using woos logic
	storageDir := woos.MakeFolder(global.Storage.CertsDir, woos.CertDir)

	// Fallback if not set in config (though DefaultApply should have handled it)
	if !storageDir.IsSet() {
		homeDir, _ := os.UserHomeDir()
		storageDir = woos.NewFolder(filepath.Join(homeDir, ".cert"))
	}

	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Println("===============================================================")
	fmt.Printf("Storage Listing: %s\n", storageDir.Path())

	if !storageDir.Exists(woos.Folder("")) {
		fmt.Println("⚠  Listing does not exist")
	} else {
		// Use Folder.ReadFiles to simplify filtering
		files, err := storageDir.ReadFiles()
		if err != nil {
			fmt.Printf("⚠  Cannot read directory: %v\n", err)
		} else {
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
	}
}

func handleGossipInit(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}

	// Determine key path (use certs directory)
	certsDir := woos.MakeFolder(global.Storage.CertsDir, woos.CertDir)
	keyPath := filepath.Join(certsDir.Path(), "gossip.key")

	// Generate key if it doesn't exist
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logger.Info("Generating gossip private key...")
		if err := security.GenerateNewKeyFile(keyPath); err != nil {
			logger.Fatal("Failed to generate key: ", err)
		}
		logger.Info("Generated gossip key: ", keyPath)

		// Set secure permissions
		os.Chmod(keyPath, 0600)
	} else {
		logger.Info("Gossip key already exists: ", keyPath)
	}

	// Display configuration guidance
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

	// Check if gossip is configured
	if &global.Gossip == nil || global.Gossip.PrivateKeyFile == "" {
		logger.Fatal("Gossip not configured. Run 'agbero gossip init' first.")
	}

	// Verify key exists
	keyPath := global.Gossip.PrivateKeyFile
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		logger.Fatalf("Gossip key not found: %s\nRun 'agbero gossip init' to generate it.", keyPath)
	}

	// Load key and generate token
	tm, err := security.LoadKeys(keyPath)
	if err != nil {
		logger.Fatal("Error loading gossip key: ", err)
	}

	// Set default TTL (30 days)
	if gossipTTL == 0 {
		gossipTTL = 720 * time.Hour // 30 days
	}

	token, err := tm.Mint(gossipService, gossipTTL)
	if err != nil {
		logger.Fatal("Error generating token: ", err)
	}

	// Output token
	fmt.Printf("\nGossip token for service: %s\n", gossipService)
	fmt.Printf("TTL: %s\n", gossipTTL)
	fmt.Println("--------------------------")
	fmt.Println(token)
	fmt.Println("--------------------------")

	// Usage example
	fmt.Printf("\nUse in your service metadata:\n")
	fmt.Printf(`{"token":"%s","port":8080,"host":"%s.example.com","path":"/"}`, token, gossipService)
	fmt.Println()
}

func handleGossipStatus(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Fatal("Error loading config: ", err)
	}

	fmt.Println("\nGossip Configuration Status")
	fmt.Println("===========================")

	if &global.Gossip == nil || !global.Gossip.Enabled {
		fmt.Println("Status: DISABLED")
		fmt.Println("\nTo enable: agbero gossip init")
		return
	}

	fmt.Println("Status: ENABLED")
	fmt.Printf("Port: %d\n", global.Gossip.Port)

	// Check key
	if global.Gossip.PrivateKeyFile != "" {
		if _, err := os.Stat(global.Gossip.PrivateKeyFile); err == nil {
			fmt.Printf("Private key: %s (exists)\n", global.Gossip.PrivateKeyFile)

			// Test key validity
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

	// Seeds
	if len(global.Gossip.Seeds) > 0 {
		fmt.Printf("Cluster seeds: %v\n", global.Gossip.Seeds)
	} else {
		fmt.Println("Cluster seeds: none (standalone mode)")
	}

	// Encryption
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
