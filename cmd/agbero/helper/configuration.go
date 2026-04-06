package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	discovery "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
	"github.com/olekukonko/ll"
)

type Configuration struct {
	p *Helper
}

func (c *Configuration) Validate(configFile string) error {
	global, err := loadGlobal(configFile)
	if err != nil {
		return err
	}
	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(c.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	u := ui.New()
	u.SectionHeader("Config validation")
	u.KeyValueBlock("", []ui.KV{
		{Label: "Config file", Value: configFile},
		{Label: "Hosts dir", Value: global.Storage.HostsDir.Path()},
		{Label: "Hosts found", Value: fmt.Sprintf("%d", len(hosts))},
	})
	u.SuccessLine("configuration is valid")
	return nil
}

func (c *Configuration) Reload(configFile string) error {
	global, err := loadGlobal(configFile)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}
	if global.Storage.DataDir == "" {
		return fmt.Errorf("data_dir not configured")
	}

	pidFile := global.Storage.DataDir.FilePath("agbero.pid")
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("could not read pid file %s: %w", pidFile, err)
	}

	pid := 0
	if _, err := fmt.Sscan(strings.TrimSpace(string(b)), &pid); err != nil {
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

func (c *Configuration) Path(configFile string) {
	fmt.Println(configFile)
}

func (c *Configuration) View(configFile, editor string) {
	if editor != "" {
		runEditor(editor, configFile)
		return
	}
	content, err := os.ReadFile(configFile)
	if err != nil {
		ui.New().ErrorHint("failed to read file", err.Error())
		return
	}
	u := ui.New()
	u.SectionHeader("Config file")
	u.KeyValue("Path", configFile)
	fmt.Println(string(content))
}

func (c *Configuration) Edit(configFile string) error {
	editor := os.Getenv("EDITOR")

	// Build fallback chain
	var candidates []string
	if editor != "" {
		candidates = append(candidates, editor)
	}

	if runtime.GOOS == "windows" {
		candidates = append(candidates, "notepad")
	} else {
		candidates = append(candidates, "nano", "vi", "vim")
	}

	// Find the first available editor
	var cmd *exec.Cmd
	for _, cand := range candidates {
		parts := strings.Fields(cand)
		if len(parts) == 0 {
			continue
		}
		if _, err := exec.LookPath(parts[0]); err == nil {
			cmd = exec.Command(parts[0], append(parts[1:], configFile)...)
			break
		}
	}

	if cmd == nil {
		return fmt.Errorf("no suitable text editor found (tried: %s)", strings.Join(candidates, ", "))
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func ResolveConfigPath(logger *ll.Logger, flagPath string) (string, bool) {
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

	ctx := setup.NewContext(logger)
	if _, err := os.Stat(ctx.Paths.ConfigFile); err == nil {
		return ctx.Paths.ConfigFile, true
	}

	return "", false
}

func InitConfiguration(logger *ll.Logger, targetDir string) (string, error) {
	ctx := setup.NewContext(logger)
	if targetDir != "" {
		base := expect.NewFolder(targetDir)
		ctx.Paths.BaseDir = base
		ctx.Paths.ConfigFile = base.FilePath(woos.DefaultConfigName)
		ctx.Paths.HostsDir = base.Sub(woos.HostDir)
		ctx.Paths.CertsDir = base.Sub(woos.CertDir)
		ctx.Paths.DataDir = base.Sub(woos.DataDir)
		ctx.Paths.LogsDir = base.Sub(woos.LogDir)
		ctx.Paths.WorkDir = base.Sub(woos.WorkDir)
	}
	err := setup.NewHome(ctx).Run()
	return ctx.Paths.ConfigFile, err
}

// InstallConfiguration prepares agbero for service registration. The decision
// tree is:
//
// If an existing config is discoverable (cwd, AGBERO_HOME, or platform
//
//	home), load it and ensure the CA is installed against the certs_dir it
//	declares. Return the existing path — no new installation is created.
//
// If here is true, scaffold a new installation in the current directory.
//
// Otherwise scaffold a new installation in the platform home directory.
//
// Returning an "already exists" error signals callers to reuse the path
// without treating it as a failure.
func InstallConfiguration(logger *ll.Logger, here bool) (string, error) {
	if here {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return InitConfiguration(logger, cwd)
	}

	existing, found := ResolveConfigPath(logger, "")
	if found {
		global, err := loadGlobal(existing)
		if err == nil && global.Storage.CertsDir != "" {
			certsDir := global.Storage.CertsDir
			if !tlss.IsCARootInstalled(certsDir) {
				loc := tlss.NewLocal(logger, newDiskStore(certsDir))
				if err := loc.InstallCARootIfNeeded(); err != nil {
					logger.Warn("CA install skipped: ", err)
				}
			}
		}
		return existing, woos.ErrConfigExists
	}

	ctx := setup.NewContext(logger)
	return InitConfiguration(logger, ctx.Paths.BaseDir.Path())
}
