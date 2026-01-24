package main

import (
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
		return flagPath, false // User provided path, return it even if missing (caller handles error)
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

// ensureConfig checks if config exists, if not, generates a default one.
func ensureConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	logger.Fields("path", path).Info("config not found, generating default")

	// Create directory if needed (e.g. if path is ~/.config/agbero/config.hcl)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Calculate hosts_dir relative to config file for portability
	hostsDirVal := "./hosts.d"

	defaultHCL := fmt.Sprintf(`bind {
  http    = [":8080"]
  # https   = [":8443"] # Uncomment to enable HTTPS
  metrics = ":9090"
}

hosts_dir = "%s"
le_email = "admin@example.com"
development = true

# trusted_proxies = ["127.0.0.1/32"]

timeouts {
  read  = "10s"
  write = "30s"
}

rate_limits {
  global {
    requests = 120
    window   = "1s"
  }
  auth {
    requests = 10
    window   = "1m"
  }
}
`, hostsDirVal)

	if err := os.WriteFile(path, []byte(defaultHCL), 0644); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}

	// Also create the hosts directory
	hostsDir := filepath.Join(dir, hostsDirVal)
	if err := os.MkdirAll(hostsDir, 0755); err != nil {
		logger.Warn("failed to create hosts directory: %v", err)
	} else {
		// Create a sample host file
		sampleHost := `domains = ["localhost"]

route "/" {
  web {
    root = "."
    directory = true
  }
}
`
		_ = os.WriteFile(filepath.Join(hostsDir, "localhost.hcl"), []byte(sampleHost), 0644)
	}

	logger.Fields("file", path).Info("default configuration created")
	return nil
}

// loadConfig parses the config and ensures hosts_dir is absolute.
// If hosts_dir is relative (e.g. "./hosts.d"), it resolves it relative to the config file.
func loadConfig(path string) (*alaye.Global, error) {
	// 1. Get Absolute Path of Config File
	absConfigPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	// 2. Parse Config
	var global alaye.Global
	parser := core.NewParser(absConfigPath)
	if err := parser.Unmarshal(&global); err != nil {
		return nil, err
	}

	// 3. Resolve hosts_dir
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

		defaultHCL := `bind {
  http    = [":80"]
  https   = [":443"]
  metrics = ":9090"
}

hosts_dir = "./hosts.d"
le_email = "admin@example.com"
trusted_proxies = ["127.0.0.1/32"]
max_header_bytes = 1048576
tls_storage_dir  = "/var/lib/agbero/certmagic"

timeouts {
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

rate_limits {
  ttl         = "30m"
  max_entries = 100000
  auth_prefixes = ["/login", "/otp", "/auth"]

  global {
    requests = 120
    window   = "1s"
    burst    = 240
  }

  auth {
    requests = 10
    window   = "1m"
    burst    = 10
  }
}
`

		if err := os.WriteFile(configFile, []byte(defaultHCL), 0644); err != nil {
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
	fmt.Print(`
   _____         ___.                        
  /  _  \    ____\_ |__   ___________  ____  
 /  /_\  \  / ___\| __ \_/ __ \_  __ \/  _ \ 
/    |    \/ /_/  > \_\ \  ___/|  | \(  <_> )
\____|__  /\___  /|___  /\___  >__|   \____/ 
        \//_____/     \/     \/              
`)
}

// Get executable name for user-friendly error messages
func getExecutableName() string {
	if len(os.Args) > 0 {
		base := filepath.Base(os.Args[0])
		// If it's a temp binary from "go run", show "agbero" instead
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

	// Check for macOS launchctl errors
	if runtime.GOOS == "darwin" && strings.Contains(errStr, "launchctl") {
		// Parse the error to give better suggestions
		if strings.Contains(errStr, "Expecting a LaunchAgents path since the command was run as user") {
			return fmt.Errorf(
				`%s

AGBERO SERVICE SETUP HELP (macOS)
===============================================================

macOS has two types of services:
----------------------------------------------------------------
- LaunchDaemon (System Service): Runs at boot, as root, for all users
- LaunchAgent (User Service): Runs when you login, as your user, for you only

Your current command is trying to create a LaunchDaemon, but you're not root.

QUICK FIXES:
----------------------------------------------------------------
Option 1: Run as system service (requires sudo)
  sudo %s install --config "%s"
  sudo %s start --config "%s"

Option 2: Use interactive mode (recommended for development)
  %s run --config "%s"

Option 3: Build and run directly
  go build -o agbero cmd/agbero/*.go
  ./agbero run --config "%s"

Option 4: Use the Makefile helper
  make run   # Runs in interactive mode with dev config

Option 5: Install as user service (advanced)
  First, ensure the service is configured for user-level operation.
  Then: %s install --config "%s"

WHAT'S HAPPENING:
----------------------------------------------------------------
1. You're running: %s %s
2. This tries to create a system-level LaunchDaemon
3. Regular users can't create system LaunchDaemons
4. macOS suggests using 'launchctl bootstrap' with root privileges

NEXT STEPS:
----------------------------------------------------------------
For development: Use "run" command or "make run"
For production: Use sudo or configure as user service
`,
				err,
				exeName, configPath,
				exeName, configPath,
				exeName, configPath,
				configPath,
				exeName, configPath,
				exeName, cmd)
		}

		if strings.Contains(errStr, "Load failed: 5") {
			return fmt.Errorf(
				`%s

AGBERO SERVICE TROUBLESHOOTING (macOS)
===============================================================

The service failed to load. This usually means:
- Permission issues with launchd
- Missing plist file
- Service already running with conflicts

TRY THESE COMMANDS:
----------------------------------------------------------------
1. Check if service is already loaded:
   sudo launchctl list | grep agbero
   launchctl list | grep agbero

2. Remove any existing service (if needed):
   sudo launchctl unload /Library/LaunchDaemons/agbero.plist 2>/dev/null || true
   launchctl unload ~/Library/LaunchAgents/agbero.plist 2>/dev/null || true

3. Reinstall with sudo:
   sudo %s uninstall --config "%s"
   sudo %s install --config "%s"
   sudo %s start --config "%s"

4. Or use interactive mode (easier for now):
   %s run --dev --config "%s"

DIAGNOSTIC COMMANDS:
----------------------------------------------------------------
- Check launchd logs: sudo log show --predicate 'subsystem == "com.apple.launchd"'
- Check system logs: console.app
- Verify plist: sudo plutil -lint /Library/LaunchDaemons/agbero.plist
`,
				err,
				exeName, configPath,
				exeName, configPath,
				exeName, configPath,
				exeName, configPath)
		}
	}

	// Check for Linux systemd errors
	if runtime.GOOS == "linux" && strings.Contains(errStr, "systemctl") {
		return fmt.Errorf(
			`%s

AGBERO SERVICE HELP (Linux)
===============================================================

Linux services require root privileges via sudo.

QUICK FIXES:
----------------------------------------------------------------
Option 1: Run with sudo
  sudo %s %s --config "%s"

Option 2: Use interactive mode
  %s run --config "%s"

Option 3: Check service status
  sudo systemctl status agbero

USEFUL COMMANDS:
----------------------------------------------------------------
- Start service:    sudo systemctl start agbero
- Stop service:     sudo systemctl stop agbero
- Enable at boot:   sudo systemctl enable agbero
- View logs:        sudo journalctl -u agbero -f
- Reload config:    sudo systemctl daemon-reload
`,
			err,
			exeName, cmd, configPath,
			exeName, configPath)
	}

	// Generic service error
	return fmt.Errorf(
		`%s

AGBERO SERVICE ERROR
===============================================================

Failed to %s the service. Try these options:

QUICK FIXES:
----------------------------------------------------------------
1. Run with elevated privileges:
   sudo %s %s --config "%s"

2. Use interactive mode instead:
   %s run --config "%s"

3. Check if service is already running:
   %s validate --config "%s"

COMMON ISSUES:
----------------------------------------------------------------
- Missing permissions (need sudo/Administrator)
- Service already installed/running
- Corrupted service configuration
- Port 80/443 already in use
`,
		err,
		cmd,
		exeName, cmd, configPath,
		exeName, configPath,
		exeName, configPath)
}

func showHelpExamples(configPath string) {
	exeName := getExecutableName()

	fmt.Println("\n" + woos.Name + " - " + woos.Description + " v" + version)
	fmt.Println("\n===============================================================")
	fmt.Println("USAGE EXAMPLES")
	fmt.Println("===============================================================")
	fmt.Println("")
	fmt.Println("DEVELOPMENT / TESTING:")
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("  %s run --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s run --dev --config \"%s\"\n", exeName, configPath)
	fmt.Println("")
	fmt.Println("CONFIGURATION MANAGEMENT:")
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("  %s validate --config \"%s\"\n", exeName, configPath)
	fmt.Printf("  %s hosts --config \"%s\"\n", exeName, configPath)
	fmt.Println("")

	if runtime.GOOS == "darwin" {
		fmt.Println("macOS SERVICE MANAGEMENT:")
		fmt.Println("----------------------------------------------------------------")
		fmt.Println("System Service (runs at boot, requires sudo):")
		fmt.Printf("  sudo %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  sudo %s start --config \"%s\"\n", exeName, configPath)
		fmt.Println("")
		fmt.Println("User Service (runs when logged in):")
		fmt.Printf("  %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  %s start --config \"%s\"\n", exeName, configPath)
		fmt.Println("")
		fmt.Println("Service Commands:")
		fmt.Printf("  sudo launchctl list | grep agbero      # Check system service\n")
		fmt.Printf("  launchctl list | grep agbero          # Check user service\n")
		fmt.Printf("  sudo launchctl unload /Library/LaunchDaemons/agbero.plist  # Stop system service\n")

	} else if runtime.GOOS == "linux" {
		fmt.Println("LINUX SERVICE MANAGEMENT:")
		fmt.Println("----------------------------------------------------------------")
		fmt.Println("System Service (requires sudo):")
		fmt.Printf("  sudo %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  sudo %s start --config \"%s\"\n", exeName, configPath)
		fmt.Println("")
		fmt.Println("Service Commands:")
		fmt.Printf("  sudo systemctl status agbero          # Check status\n")
		fmt.Printf("  sudo journalctl -u agbero -f          # View logs\n")
		fmt.Printf("  sudo systemctl enable agbero          # Enable at boot\n")

	} else if runtime.GOOS == "windows" {
		fmt.Println("WINDOWS SERVICE MANAGEMENT:")
		fmt.Println("----------------------------------------------------------------")
		fmt.Println("System Service (run as Administrator):")
		fmt.Printf("  %s install --config \"%s\"\n", exeName, configPath)
		fmt.Printf("  %s start --config \"%s\"\n", exeName, configPath)
		fmt.Println("")
		fmt.Println("Service Commands:")
		fmt.Printf("  sc query agbero                       # Check service status\n")
		fmt.Printf("  services.msc                          # Open Services GUI\n")
		fmt.Printf("  net start agbero                      # Start service\n")
		fmt.Printf("  net stop agbero                       # Stop service\n")
	}

	fmt.Println("\n===============================================================")
	fmt.Println("For more options, use: " + exeName + " --help")
	fmt.Println("===============================================================")
}

func showCertInfo(configPath string) {
	global, err := loadConfig(configPath)
	if err != nil {
		logger.Warn("Could not load config to show cert info: %v", err)
		return
	}

	// Determine storage directory
	storageDir := global.TLSStorageDir
	if storageDir == "" {
		homeDir, _ := os.UserHomeDir()
		storageDir = filepath.Join(homeDir, ".cert")
	}

	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Println("===============================================================")
	fmt.Printf("Storage Directory: %s\n", storageDir)

	// Check if directory exists
	if _, err := os.Stat(storageDir); os.IsNotExist(err) {
		fmt.Println("⚠  Directory does not exist")
	} else {
		// List certificates
		files, err := os.ReadDir(storageDir)
		if err != nil {
			fmt.Printf("⚠  Cannot read directory: %v\n", err)
		} else {
			certCount := 0
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".pem") {
					certCount++
				}
			}
			fmt.Printf("Found %d certificate(s)\n", certCount)

			if certCount > 0 {
				fmt.Println("\nAvailable certificates:")
				for _, file := range files {
					if !file.IsDir() && strings.HasSuffix(file.Name(), ".pem") {
						fullPath := filepath.Join(storageDir, file.Name())
						info, err := os.Stat(fullPath)
						if err == nil {
							fmt.Printf("  • %s (%s, %s)\n",
								file.Name(),
								humanize.Bytes(uint64(info.Size())),
								info.ModTime().Format("2006-01-02"))
						}
					}
				}
			}
		}
	}

	fmt.Println("\nTo use existing certificates from this directory:")
	fmt.Println("  In your host config, use:")
	fmt.Println(`  tls {
    mode = "local"
    local {
      cert_file = "` + filepath.Join(storageDir, "localhost.pem") + `"
      key_file  = "` + filepath.Join(storageDir, "localhost.key.pem") + `"
    }
  }`)
}
