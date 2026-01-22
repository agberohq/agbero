package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// loadConfig parses the config and ensures hosts_dir is absolute.
// If hosts_dir is relative (e.g. "./hosts.d"), it resolves it relative to the config file.
func loadConfig(path string) (*woos.GlobalConfig, error) {
	// 1. Get Absolute Path of Config File
	absConfigPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	// 2. Parse Config
	var global woos.GlobalConfig
	parser := woos.NewParser(absConfigPath)
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
		baseDir = `C:\ProgramData\agbero`
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

		// For Windows, use relative path to avoid escape char issues in HCL strings
		safeHostsDir := hostsDir
		if runtime.GOOS == "windows" {
			safeHostsDir = "./hosts.d"
		}

		defaultHCL := fmt.Sprintf(`bind = ":80 :443"
hosts_dir = "%s"
le_email = "admin@example.com"
trusted_proxies = ["127.0.0.1/32"]
# tls_storage_dir = "/var/lib/agbero/certmagic"

timeouts {
  read  = "10s"
  write = "30s"
}

rate_limits {
  ttl = "30m"
  global {
    requests = 120
    window   = "1s"
  }
}
`, safeHostsDir)

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

	hm := discovery.NewHost(global.HostsDir)
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

	hm := discovery.NewHost(global.HostsDir)
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
