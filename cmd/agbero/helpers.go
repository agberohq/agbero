package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/dustin/go-humanize"
)

// Embedded Assets
//
//go:embed data/config.hcl
var configDevTmpl string

//go:embed data/config_system.hcl
var configSystemTmpl string

//go:embed data/sample.hcl
var hostSampleTmpl string

//go:embed data/banner.txt
var bannerTmpl string

// resolveConfigPath implements the search order:
// 1. Explicit Flag
// 2. Current Working Directory (agbero.hcl)
// 3. User Config Dir (~/.config/agbero/config.hcl)
// 4. System Config Dir (/etc/agbero/config.hcl)
// Returns the path to use and whether it currently exists.
func resolveConfigPath(flagPath string) (string, bool) {
	// 1. Explicit Flag
	if flagPath != "" {
		if _, err := os.Stat(flagPath); err == nil {
			return flagPath, true
		}
		return flagPath, false // User provided path, return it even if missing
	}

	// 2. CWD
	cwd, _ := os.Getwd()
	cwdPath := filepath.Join(cwd, "agbero.hcl")
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath, true
	}

	// 3. User Config Dir
	userDir, _ := os.UserConfigDir()
	userPath := filepath.Join(userDir, "agbero", "config.hcl")
	if _, err := os.Stat(userPath); err == nil {
		return userPath, true
	}

	// 4. System Config Dir
	var sysPath string
	if runtime.GOOS == "windows" {
		sysPath = filepath.Join(os.Getenv("ProgramData"), "agbero", "config.hcl")
	} else {
		sysPath = "/etc/agbero/config.hcl"
	}
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath, true
	}

	// Default fallback for generation: CWD
	return cwdPath, false
}

// ensureConfig checks if config exists, if not, generates a default one using embedded templates.
func ensureConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	logger.Fields("path", path).Info("config not found, generating default")

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Calculate hosts_dir relative to config file for portability
	hostsDirVal := "./hosts.d"

	// Inject hosts_dir into the template
	content := fmt.Sprintf(configDevTmpl, hostsDirVal)

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}

	// Create the hosts directory and sample
	hostsDir := filepath.Join(dir, hostsDirVal)
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		logger.Warn("failed to create hosts directory: %v", err)
	} else {
		_ = os.WriteFile(filepath.Join(hostsDir, "localhost.hcl"), []byte(hostSampleTmpl), 0644)
	}

	logger.Fields("file", path).Info("default configuration created")
	return nil
}

// loadConfig parses the config and ensures hosts_dir is absolute.
func loadConfig(path string) (*alaye.Global, error) {
	absConfigPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	var global alaye.Global
	parser := core.NewParser(absConfigPath)
	if err := parser.Unmarshal(&global); err != nil {
		return nil, err
	}

	if global.HostsDir != "" && !filepath.IsAbs(global.HostsDir) {
		configDir := filepath.Dir(absConfigPath)
		global.HostsDir = filepath.Join(configDir, global.HostsDir)
	}

	return &global, nil
}

func installDefaults() error {
	var baseDir, hostsDir, configFile string

	switch runtime.GOOS {
	case "windows":
		baseDir = filepath.Join("C:", "ProgramData", "agbero")
		hostsDir = filepath.Join(baseDir, "hosts.d")
		configFile = filepath.Join(baseDir, "config.hcl")
	case "darwin", "linux":
		baseDir = "/etc/agbero"
		hostsDir = filepath.Join(baseDir, "hosts.d")
		configFile = filepath.Join(baseDir, "config.hcl")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	logger.Fields("dir", baseDir).Info("creating directory")
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		logger.Fields("file", configFile).Info("writing default config")

		// Use the system template, inject relative hosts_dir
		content := fmt.Sprintf(configSystemTmpl, "./hosts.d")

		if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
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

	hm := discovery.NewHost(global.HostsDir, discovery.WithLogger(logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	logger.Fields("hosts_count", len(hosts), "hosts_dir", global.HostsDir).Info("configuration is valid")
	return nil
}

func listHosts(path string) error {
	global, err := loadConfig(path)
	if err != nil {
		return err
	}

	hm := discovery.NewHost(global.HostsDir, discovery.WithLogger(logger))
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
	if runtime.GOOS == "darwin" && strings.Contains(errStr, "launchctl") {
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
	fmt.Println("")
	fmt.Println("CONFIGURATION:")
	fmt.Printf("  %s validate --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s hosts --config \"%s\"\n", exeName, configPath)
	fmt.Println("")

	if runtime.GOOS == "darwin" {
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
		logger.Warn("Could not load config: %v", err)
		return
	}

	storageDir := global.TLSStorageDir
	if storageDir == "" {
		homeDir, _ := os.UserHomeDir()
		storageDir = filepath.Join(homeDir, ".cert")
	}

	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Println("===============================================================")
	fmt.Printf("Storage Directory: %s\n", storageDir)

	if _, err := os.Stat(storageDir); os.IsNotExist(err) {
		fmt.Println("⚠  Directory does not exist")
	} else {
		files, err := os.ReadDir(storageDir)
		if err != nil {
			fmt.Printf("⚠  Cannot read directory: %v\n", err)
		} else {
			count := 0
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".pem") {
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
