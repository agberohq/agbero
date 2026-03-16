package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/installer"
)

type Configuration struct {
	p *Helper
}

func (c *Configuration) Validate(configFile string) error {
	global, err := loadGlobal(configFile)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHost(hostsFolder, discovery.WithLogger(c.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	c.p.Logger.Fields(
		"hosts_count", len(hosts),
		"hosts_dir", global.Storage.HostsDir,
	).Info("configuration is valid")
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

	pidFile := filepath.Join(global.Storage.DataDir, "agbero.pid")
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
		fmt.Printf("failed to read file: %v\n", err)
		return
	}
	fmt.Printf("\033[1;34m%s\033[0m\n\n", configFile)
	fmt.Println(string(content))
}

func (c *Configuration) Edit(configFile string) {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	runEditor(editor, configFile)
}

func ResolveConfigPath(flagPath string) (string, bool) {
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

	ctx := installer.NewContext(nil, "")
	if _, err := os.Stat(ctx.Paths.ConfigFile); err == nil {
		return ctx.Paths.ConfigFile, true
	}

	return "", false
}

func InitConfiguration(targetDir string) (string, error) {
	ctx := installer.NewContext(nil, "")
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

func InstallConfiguration(here bool) (string, error) {
	if here {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return InitConfiguration(cwd)
	}
	ctx := installer.NewContext(nil, "")
	return InitConfiguration(ctx.Paths.BaseDir.Path())
}
