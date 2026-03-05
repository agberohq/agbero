package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"math/big"
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
	"git.imaxinacion.net/aibox/agbero/internal/pkg/tlss"
	"github.com/dustin/go-humanize"
	"github.com/integrii/flaggy"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

// Embedded Assets
//
//go:embed data/agbero.hcl
var configTmpl string

//go:embed data/banner.txt
var bannerTmpl string

//go:embed data/hosts.d/web.hcl
var tplWebHcl []byte

//go:embed data/hosts.d/admin.hcl
var tplAdminHcl []byte

type helper struct {
	logger *ll.Logger
}

func newHelper(logger *ll.Logger) *helper {
	return &helper{logger: logger}
}

func (h *helper) welcome() {
	fmt.Println(bannerTmpl)
	fmt.Printf("\033[1;34m%s\033[0m - %s\n", woos.Name, woos.Description)
	fmt.Printf("\033[90mVersion: %s\033[0m\n", woos.Version)
	fmt.Printf("\033[90mDate: %s\033[0m\n\n", woos.Date)
}

func (h *helper) resolveConfigPath(flagPath string) (string, bool) {
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

func (h *helper) generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		b[i] = charset[num.Int64()]
	}
	return string(b), nil
}

func (h *helper) initConfiguration(targetDir string) (string, error) {
	if targetDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		targetDir = cwd
	}

	if err := os.MkdirAll(targetDir, woos.DirPerm); err != nil {
		return "", err
	}

	configFile := filepath.Join(targetDir, woos.DefaultConfigName)

	if _, err := os.Stat(configFile); err == nil {
		return "", fmt.Errorf("configuration already exists at %s", configFile)
	}

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

	content := strings.ReplaceAll(configTmpl, "{HOST_DIR}", woos.HostDir.String())
	content = strings.ReplaceAll(content, "{CERTS_DIR}", woos.CertDir.String())
	content = strings.ReplaceAll(content, "{DATA_DIR}", woos.DataDir.String())
	content = strings.ReplaceAll(content, "{LOGS_DIR}", woos.LogDir.String())

	secret, _ := h.generateSecureKey(128)

	password, err := h.generateRandomPassword(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	content = strings.ReplaceAll(content, "{ADMIN_PASSWORD}", string(hash))
	content = strings.ReplaceAll(content, "{ADMIN_SECRET}", secret)

	if err := os.WriteFile(configFile, []byte(content), woos.FilePermSecured); err != nil {
		return "", err
	}

	hostsDir := filepath.Join(targetDir, woos.HostDir.String())

	adminFile := filepath.Join(hostsDir, "admin.hcl")
	if err := os.WriteFile(adminFile, tplAdminHcl, woos.FilePerm); err != nil {
		return "", err
	}

	webFile := filepath.Join(hostsDir, "web.hcl")
	if err := os.WriteFile(webFile, tplWebHcl, woos.FilePerm); err != nil {
		return "", err
	}

	fmt.Println("")
	fmt.Println("===============================================================")
	fmt.Println("CONFIGURATION INITIALIZED")
	fmt.Println("===============================================================")
	fmt.Printf("Config File:    %s\n", configFile)
	fmt.Printf("Admin User:     admin\n")
	fmt.Printf("Admin Password: %s\n", password)
	fmt.Println("===============================================================")
	fmt.Println("Note: This password is now hashed in your config file.")
	fmt.Println("")

	return configFile, nil
}

func (h *helper) installConfiguration(here bool) (string, error) {
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

	return h.initConfiguration(targetDir)
}

func (h *helper) reloadService(configFile string) error {
	global, err := h.loadConfig(configFile)
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

func (h *helper) loadConfig(configFile string) (*alaye.Global, error) {
	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		return nil, err
	}
	abs, _ := filepath.Abs(configFile)
	woos.DefaultApply(global, abs)
	return global, nil
}

func (h *helper) validateConfig(configFile string) error {
	global, err := h.loadConfig(configFile)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHost(hostsFolder, discovery.WithLogger(h.logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	h.logger.Fields("hosts_count", len(hosts), "hosts_dir", global.Storage.HostsDir).Info("configuration is valid")
	return nil
}

func (h *helper) listHosts(configFile string) error {
	global, err := h.loadConfig(configFile)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHost(hostsFolder, discovery.WithLogger(h.logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		h.logger.Warn("no hosts found")
		return nil
	}
	for name, c := range hosts {
		h.logger.Fields(
			"host_id", name,
			"domains", c.Domains,
			"routes", len(c.Routes),
		).Info("configured host")
	}
	return nil
}

func (h *helper) handleServiceError(err error, cmd string, configPath string) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	exeName := h.getExecutableName()

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

func (h *helper) getExecutableName() string {
	if len(os.Args) > 0 {
		return filepath.Base(os.Args[0])
	}
	return woos.Name
}

func (h *helper) showHelpExamples(configPath string) {
	exeName := h.getExecutableName()
	fmt.Println("\n" + woos.Name + " - " + woos.Description + " v" + woos.Version)
	fmt.Println("\n===============================================================")
	fmt.Println("USAGE EXAMPLES")
	fmt.Println("===============================================================")
	fmt.Println("")
	fmt.Println("SCAFFOLDING:")
	fmt.Printf("  %s init             # Create config in current folder\n", exeName)
	fmt.Printf("  %s install          # Create config in system folder & install service (requires root)\n", exeName)
	fmt.Println("")
	fmt.Println("EXECUTION:")
	fmt.Printf("  %s run              # Run using discovered config\n", exeName)
	fmt.Printf("  %s run --dev        # Run with debug logging\n", exeName)
	fmt.Printf("  %s reload           # Hot reload running instance\n", exeName)
	fmt.Println("")
	fmt.Println("API MANAGEMENT:")
	fmt.Printf("  %s key init         # Generate internal auth key\n", exeName)
	fmt.Printf("  %s key gen -s myapp # Generate token for app 'myapp'\n", exeName)
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

func (h *helper) showCertInfo(configPath string) {
	global, err := h.loadConfig(configPath)
	if err != nil {
		h.logger.Warnf("Could not load config: %v", err)
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

func (h *helper) handleCertCommands(install, uninstall, list, info bool, force bool, certDir string) {
	installer := tlss.NewInstaller(h.logger)

	if global, err := h.loadConfig(configPath); err == nil && global.Storage.CertsDir != "" {
		folder := woos.NewFolder(global.Storage.CertsDir)
		_ = installer.SetStorageDir(folder)
		h.logger.Fields("dir", folder.Path()).Info("storage directory")
	}

	if uninstall {
		h.logger.Info("Uninstalling CA...")

		if err := installer.UninstallCARoot(); err != nil {
			h.logger.Warnf("System trust store cleanup: %v (might already be removed)", err)
		} else {
			h.logger.Info("Removed CA from system trust store")
		}

		dir := installer.CertDir.Path()
		files, err := os.ReadDir(dir)
		if err != nil {
			h.logger.Warnf("Could not read dir: %v", err)
			return
		}

		count := 0
		for _, f := range files {
			name := f.Name()
			if strings.HasSuffix(name, ".pem") ||
				strings.HasSuffix(name, ".key") ||
				strings.HasSuffix(name, ".crt") {

				if err := os.Remove(filepath.Join(dir, name)); err == nil {
					count++
				}
			}
		}

		if count > 0 {
			h.logger.Infof("Deleted %d certificate files from disk", count)
		} else {
			h.logger.Warn("No certificate files found to delete")
		}

		h.logger.Info("Uninstall complete")
		return
	}

	if install {
		if tlss.IsCARootInstalled(installer.CertDir.Path()) && !force {
			h.logger.Info("CA root is already installed. Use --force to reinstall.")
			return
		}
		if err := installer.InstallCARootIfNeeded(); err != nil {
			h.logger.Fatal("Failed to install CA: ", err)
		}
		h.logger.Info("CA root installed successfully.")
		return
	}

	if list {
		certs, err := installer.ListCertificates()
		if err != nil {
			h.logger.Fatal("Failed to list certificates: ", err)
		}

		if len(certs) == 0 {
			h.logger.Warn("No certificates found")
			return
		}

		h.logger.Infof("Found %d certificates:", len(certs))
		for i, cert := range certs {
			h.logger.Printf("  %d. %s\n", i+1, cert)
		}
		return
	}

	if info {
		h.showCertInfo(configPath)
		return
	}

	flaggy.ShowHelpAndExit("cert")
}

func (h *helper) handleKeyCommands(init, gen bool, service string, ttl time.Duration) {
	if init {
		h.handleKeyInit()
		return
	}
	if gen {
		h.handleKeyGen(service, ttl)
		return
	}
	flaggy.ShowHelpAndExit("key")
}

func (h *helper) handleKeyInit() {
	global, err := h.loadConfig(configPath)
	var targetPath string

	// Use config value if set, otherwise default to certs dir
	if err == nil && global.Security.InternalAuthKey != "" {
		targetPath = global.Security.InternalAuthKey
	} else {
		sysPaths := woos.DefaultPaths()
		targetPath = filepath.Join(sysPaths.CertsDir.Path(), "internal_auth.key")
	}

	if _, err := os.Stat(targetPath); err == nil {
		h.logger.Warn("key file already exists: ", targetPath)
		return
	}

	// Ensure dir exists
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		h.logger.Fatal("failed to create directory: ", err)
	}

	if err := security.GenerateNewKeyFile(targetPath); err != nil {
		h.logger.Fatal("failed to generate key: ", err)
	}

	h.logger.Info("generated internal auth key: ", targetPath)
	fmt.Println("\nAdd this to your agbero.hcl under the security block:")
	fmt.Printf(`
security {
  enabled = true
  internal_auth_key = "%s"
  # ... other security settings
}
`, targetPath)
}

func (h *helper) handleKeyGen(service string, ttl time.Duration) {
	if service == "" {
		h.logger.Fatal("error: --service name is required")
	}

	global, err := h.loadConfig(configPath)
	if err != nil {
		h.logger.Fatal("failed to load config: ", err)
	}

	keyPath := global.Security.InternalAuthKey
	if keyPath == "" {
		// Fallback to default if not in config
		sysPaths := woos.DefaultPaths()
		defaultPath := filepath.Join(sysPaths.CertsDir.Path(), "internal_auth.key")
		if _, err := os.Stat(defaultPath); err == nil {
			keyPath = defaultPath
		}
	}

	if keyPath == "" {
		h.logger.Fatal("error: 'security.internal_auth_key' is not set in config and default file not found")
	}

	tm, err := security.LoadKeys(keyPath)
	if err != nil {
		h.logger.Fatal("failed to load private key: ", err)
	}

	if ttl == 0 {
		ttl = 365 * 24 * time.Hour // Default 1 year
	}

	token, err := tm.Mint(service, ttl)
	if err != nil {
		h.logger.Fatal("failed to mint token: ", err)
	}

	fmt.Printf("\nAPI Token for service: %s\n", service)
	fmt.Printf("Expires: %s (%s)\n", time.Now().Add(ttl).Format(time.RFC3339), ttl)
	fmt.Println("------------------------------------------------------------")
	fmt.Println(token)
	fmt.Println("------------------------------------------------------------")
}

func (h *helper) handleClusterSecret() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		h.logger.Fatal("Random generation failed: ", err)
	}

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

func (h *helper) generateSecureKey(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(b)
	return encoded, nil
}
