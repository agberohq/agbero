// cmd/agbero/helpers.go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/installer"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/dustin/go-humanize"
	"github.com/integrii/flaggy"
	"github.com/olekukonko/ll"
)

type helper struct {
	logger *ll.Logger
}

func newHelper(logger *ll.Logger) *helper {
	return &helper{logger: logger}
}

func (h *helper) welcome() {
	fmt.Println(installer.BannerTmpl)
	fmt.Printf("\033[1;34m%s\033[0m - %s\n", woos.Name, woos.Description)
	fmt.Printf("\033[90mVersion: %s\033[0m\n", woos.Version)
	fmt.Printf("\033[90mDate: %s\033[0m\n\n", woos.Date)
}

func (h *helper) home(homeTarget, homeAction string) {
	ctx := installer.NewContext(logger, "")
	target := homeTarget
	openShell := false
	showContent := false
	editorCmd := ""

	// Parse action: could be "@", "@vim", "@cat", etc.
	if strings.HasPrefix(homeAction, "@") {
		if homeAction == "@" {
			openShell = true
		} else {
			showContent = true
			editorCmd = strings.TrimPrefix(homeAction, "@")
		}
	} else if homeTarget == "@" {
		target = "base"
		openShell = true
	}

	var dir string
	var filePath string

	switch strings.ToLower(target) {
	case "hosts":
		dir = ctx.Paths.HostsDir.Path()
	case "certs":
		dir = ctx.Paths.CertsDir.Path()
	case "data":
		dir = ctx.Paths.DataDir.Path()
	case "logs":
		dir = ctx.Paths.LogsDir.Path()
	case "work":
		dir = ctx.Paths.WorkDir.Path()
	case "config":
		filePath = ctx.Paths.ConfigFile
		dir = filepath.Dir(ctx.Paths.ConfigFile)
	default:
		dir = ctx.Paths.BaseDir.Path()
	}

	// Handle showing/editing files
	if showContent && filePath != "" {
		h.openWithEditor(filePath, editorCmd)
		return
	}

	// Handle shell navigation
	if openShell {
		if err := os.Chdir(dir); err != nil {
			fmt.Printf("Failed to enter directory: %v\n", err)
			return
		}

		fmt.Printf("\033[1;34mAgbero Workspace\033[0m: %s\n\n", dir)

		lsCmd := "ls"
		if runtime.GOOS == woos.Windows {
			lsCmd = "dir"
		}
		ls := exec.Command(lsCmd)
		ls.Stdout = os.Stdout
		ls.Stderr = os.Stderr
		_ = ls.Run()

		shell := os.Getenv("SHELL")
		if shell == "" {
			if runtime.GOOS == woos.Windows {
				shell = "cmd.exe"
			} else {
				shell = "/bin/sh"
			}
		}

		cmd := exec.Command(shell)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
	} else {
		if filePath != "" {
			fmt.Println(filePath)
		} else {
			fmt.Println(dir)
		}
	}
}

func (h *helper) openWithEditor(filePath string, editor string) {
	// Map of editors to commands
	editors := map[string][]string{
		"vim":   {"vim", filePath},
		"vi":    {"vi", filePath},
		"nano":  {"nano", filePath},
		"micro": {"micro", filePath},
		"code":  {"code", filePath},
		"cat":   {"cat", filePath},
		"less":  {"less", filePath},
		"more":  {"more", filePath},
	}

	// If specific editor requested
	if editor != "" {
		if cmd, ok := editors[editor]; ok {
			h.runEditor(cmd)
			return
		}
		// Try as direct command (for custom editors)
		h.runEditor([]string{editor, filePath})
		return
	}

	// No editor specified - show content with cat
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}
	fmt.Printf("\033[1;34m%s\033[0m\n\n", filePath)
	fmt.Println(string(content))
}

func (h *helper) runEditor(cmdArgs []string) {
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to open editor: %v\n", err)
	}
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

	ctx := installer.NewContext(h.logger, "")
	if _, err := os.Stat(ctx.Paths.ConfigFile); err == nil {
		return ctx.Paths.ConfigFile, true
	}

	return "", false
}

func (h *helper) initConfiguration(targetDir string) (string, error) {
	ctx := installer.NewContext(h.logger, "")

	if targetDir != "" {
		base := woos.NewFolder(targetDir)
		ctx.Paths.BaseDir = base
		ctx.Paths.ConfigFile = filepath.Join(base.Path(), woos.DefaultConfigName)
		ctx.Paths.HostsDir = base.Join(woos.HostDir.Name())
		ctx.Paths.CertsDir = base.Join(woos.CertDir.Name())
		ctx.Paths.DataDir = base.Join(woos.DataDir.Name())
		ctx.Paths.LogsDir = base.Join(woos.LogDir.Name())
		ctx.Paths.WorkDir = base.Join(woos.WorkDir.Name())
	}

	err := installer.NewHome(ctx).Run()
	return ctx.Paths.ConfigFile, err
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
		ctx := installer.NewContext(h.logger, "")
		targetDir = ctx.Paths.BaseDir.Path()
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
	ctx := installer.NewContext(h.logger, "")
	svc := installer.NewService(ctx)

	errMsg := err.Error()

	switch cmd {
	case "status":
		if strings.Contains(errMsg, "not installed") {
			return fmt.Errorf("service not installed. Run 'sudo agbero service install' first")
		}
	case "restart":
		if strings.Contains(errMsg, "not running") {
			return fmt.Errorf("service not running. Try 'sudo agbero service start'")
		}
	}

	return svc.MapError(err, cmd)
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
	fmt.Printf("  %s init             # Create config interactively in current folder\n", exeName)
	fmt.Printf("  %s install          # Create config in system folder & install service\n", exeName)
	fmt.Println("")
	fmt.Println("EXECUTION:")
	fmt.Printf("  %s run              # Run using discovered config\n", exeName)
	fmt.Printf("  %s serve .          # Serve current directory securely on the fly\n", exeName)
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
		fmt.Printf("  %s stop\n", exeName)
		fmt.Printf("  %s restart\n", exeName)
		fmt.Printf("  %s status\n", exeName)
		fmt.Printf("  %s uninstall\n", exeName)
	} else {
		fmt.Printf("  sudo %s install\n", exeName)
		fmt.Printf("  sudo %s start\n", exeName)
		fmt.Printf("  sudo %s stop\n", exeName)
		fmt.Printf("  sudo %s restart\n", exeName)
		fmt.Printf("  sudo %s status\n", exeName)
		fmt.Printf("  sudo %s uninstall\n", exeName)
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
	fmt.Printf("Store Listing: %s\n", storageDir.Path())
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
	installerLoc := tlss.NewLocal(h.logger)

	if global, err := h.loadConfig(configPath); err == nil && global.Storage.CertsDir != "" {
		folder := woos.NewFolder(global.Storage.CertsDir)
		_ = installerLoc.SetStorageDir(folder)
		h.logger.Fields("dir", folder.Path()).Info("storage directory")
	}

	if uninstall {
		h.logger.Info("Uninstalling CA...")

		if err := installerLoc.UninstallCARoot(); err != nil {
			h.logger.Warnf("System trust store cleanup: %v (might already be removed)", err)
		} else {
			h.logger.Info("Removed CA from system trust store")
		}

		dir := installerLoc.CertDir.Path()
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
		if tlss.IsCARootInstalled(installerLoc.CertDir.Path()) && !force {
			h.logger.Info("CA root is already installed. Use --force to reinstall.")
			return
		}
		if err := installerLoc.InstallCARootIfNeeded(); err != nil {
			h.logger.Fatal("Failed to install CA: ", err)
		}
		h.logger.Info("CA root installed successfully.")
		return
	}

	if list {
		certs, err := installerLoc.ListCertificates()
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

	if err == nil && global.Security.InternalAuthKey != "" {
		targetPath = global.Security.InternalAuthKey
	} else {
		ctx := installer.NewContext(h.logger, "")
		targetPath = filepath.Join(ctx.Paths.CertsDir.Path(), "internal_auth.key")
	}

	if _, err := os.Stat(targetPath); err == nil {
		h.logger.Warn("key file already exists: ", targetPath)
		return
	}

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
		ctx := installer.NewContext(h.logger, "")
		defaultPath := filepath.Join(ctx.Paths.CertsDir.Path(), "internal_auth.key")
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
		ttl = 365 * 24 * time.Hour
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
