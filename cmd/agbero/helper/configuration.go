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
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
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

	if err := global.Validate(); err != nil {
		return fmt.Errorf("global config invalid: %w", err)
	}

	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(c.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("Config validation")
		u.KeyValueBlock("", []ui.KV{
			{Label: "Config file", Value: configFile},
			{Label: "Hosts dir", Value: global.Storage.HostsDir.Path()},
			{Label: "Hosts found", Value: fmt.Sprintf("%d", len(hosts))},
		})
		u.SuccessLine("configuration is valid")
	})
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
	u := ui.New()
	u.SuccessLine(configFile)
	u.Flush()
}

func (c *Configuration) View(configFile, editor string) {

	u := ui.New()
	if editor != "" {
		runEditor(editor, configFile)
		return
	}
	content, err := os.ReadFile(configFile)
	if err != nil {
		u.ErrorHint("failed to read file", err.Error())
		u.Flush()
		return
	}

	u.Render(func() {
		u.SectionHeader("Config file")
		u.KeyValue("Path", configFile)
	})
	u.Println(string(content))
	u.Flush()
}

func (c *Configuration) Edit(configFile string) error {
	editor := os.Getenv("EDITOR")

	var candidates []string
	if editor != "" {
		candidates = append(candidates, editor)
	}

	if runtime.GOOS == "windows" {
		candidates = append(candidates, "notepad")
	} else {
		candidates = append(candidates, "nano", "vi", "vim")
	}

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

func InstallConfiguration(logger *ll.Logger, here bool) (string, error) {
	if here {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return InitConfiguration(logger, cwd)
	}

	existing, found := ResolveConfigPath(logger, "")
	var store tlsstore.Store
	if found {
		global, err := loadGlobal(existing)
		if err == nil && global.Storage.CertsDir != "" {
			certsDir := global.Storage.CertsDir
			store, err = tlsstore.NewDisk(tlsstore.DiskConfig{CertDir: certsDir})
			if err != nil {
				store = tlsstore.NewMemory()
			}
			loc := tlss.NewLocal(logger, store)
			if !loc.CAExistsInSystem() {
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
