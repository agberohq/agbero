package helper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/dustin/go-humanize"
)

type Cert struct {
	p *Helper
}

func (c *Cert) Install(configPath string, force bool) {
	certsDir, loc := c.newLocal(configPath)

	if force {
		c.p.Logger.Info("Force flag detected. Removing existing CA and regenerating...")
		_ = loc.UninstallCARoot()
		loc.RemoveCA()
	} else if tlss.IsCARootInstalled(certsDir) {
		c.p.Logger.Info("CA root is already installed. Synchronizing with system trust stores...")
		if err := loc.InstallCARootIfNeeded(); err != nil {
			c.p.Logger.Fatal("failed to synchronize CA: ", err)
		}
		c.p.Logger.Info("CA synchronization complete.")
		c.printNSSHint(loc)
		return
	}

	if err := loc.InstallCARootIfNeeded(); err != nil {
		c.p.Logger.Fatal("failed to install CA: ", err)
	}
	c.p.Logger.Info("CA root installed successfully.")
	c.printNSSHint(loc)
}

func (c *Cert) printNSSHint(loc *tlss.Local) {
	if loc.HasCertutil() {
		return
	}
	switch runtime.GOOS {
	case woos.Darwin:
		c.p.Logger.Warn(woos.NSSInstallHintDarwin)
	case woos.Linux:
		c.p.Logger.Warn(woos.NSSInstallHintLinux)
	default:
		c.p.Logger.Warn(woos.NSSInstallHintOther)
	}
}

func (c *Cert) Uninstall(configPath string) {
	certsDir, loc := c.newLocal(configPath)
	c.p.Logger.Info("uninstalling CA...")
	if err := loc.UninstallCARoot(); err != nil {
		c.p.Logger.Warnf("system trust store cleanup: %v (might already be removed)", err)
	} else {
		c.p.Logger.Info("removed CA from system trust store")
	}

	files, err := os.ReadDir(certsDir)
	if err != nil {
		c.p.Logger.Warnf("could not read dir: %v", err)
		return
	}

	count := 0
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".crt") {
			if err := os.Remove(filepath.Join(certsDir, name)); err == nil {
				count++
			}
		}
	}
	if count > 0 {
		c.p.Logger.Infof("deleted %d certificate files from disk", count)
	} else {
		c.p.Logger.Warn("no certificate files found to delete")
	}
	c.p.Logger.Info("uninstall complete")
}

func (c *Cert) List(configPath string) {
	_, loc := c.newLocal(configPath)
	certs, err := loc.ListCertificates()
	if err != nil {
		c.p.Logger.Fatal("failed to list certificates: ", err)
	}

	u := ui.New()
	u.SectionHeader("Certificates")

	if len(certs) == 0 {
		u.WarnLine("no certificates found")
		return
	}

	var rows [][]string
	for _, name := range certs {
		domain, kind := parseCertName(name)
		rows = append(rows, []string{domain, kind, name})
	}
	u.Table([]string{"Domain", "Type", "File"}, rows)
}

func (c *Cert) Info(configPath string) {
	global, err := loadGlobal(configPath)
	if err != nil {
		c.p.Logger.Warnf("could not load config: %v", err)
		return
	}

	storageDir := woos.NewFolder(global.Storage.CertsDir)
	u := ui.New()
	u.SectionHeader("Certificate store")
	u.KeyValue("Directory", storageDir.Path())

	if !storageDir.Exists("") {
		u.WarnLine("store directory does not exist")
		return
	}

	files, err := storageDir.ReadFiles()
	if err != nil {
		u.ErrorHint("cannot read directory", err.Error())
		return
	}

	var rows [][]string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pem") {
			info, _ := file.Info()
			rows = append(rows, []string{
				file.Name(),
				humanize.Bytes(uint64(info.Size())),
				info.ModTime().Format("2006-01-02"),
			})
		}
	}

	if len(rows) == 0 {
		u.WarnLine("no certificates found")
		return
	}
	u.Table([]string{"Certificate", "Size", "Modified"}, rows)
}

// newLocal constructs a tlss.Local backed by a disk store rooted at the
// certsDir from config. It returns both the certsDir path (for callers that
// need to scan files directly) and the Local instance.
func (c *Cert) newLocal(configPath string) (certsDir string, loc *tlss.Local) {
	if global, err := loadGlobal(configPath); err == nil && global.Storage.CertsDir != "" {
		certsDir = global.Storage.CertsDir
	}

	store := newDiskStore(certsDir)
	loc = tlss.NewLocal(c.p.Logger, store)
	return certsDir, loc
}

// newDiskStore creates a tlsstore.Disk for the given certsDir.
// On error (e.g. certsDir empty or unwriteable) it falls back to memory so
// that read-only operations like List still function gracefully.
func newDiskStore(certsDir string) tlsstore.Store {
	if certsDir != "" {
		ds, err := tlsstore.NewDisk(tlsstore.DiskConfig{CertDir: certsDir})
		if err == nil {
			return ds
		}
	}
	return tlsstore.NewMemory()
}

func parseCertName(name string) (domain, kind string) {
	base := strings.TrimSuffix(name, ".pem")
	base = strings.TrimSuffix(base, ".crt")
	base = strings.TrimSuffix(base, ".key")

	switch {
	case strings.HasSuffix(base, "-cert"):
		return strings.TrimSuffix(base, "-cert"), "cert"
	case strings.HasSuffix(base, "-key"):
		return strings.TrimSuffix(base, "-key"), "key"
	case name == woos.InternalAuthKeyName:
		return "internal", "auth key"
	case strings.HasPrefix(name, "ca-"):
		return "CA", strings.TrimPrefix(base, "ca-")
	default:
		return base, "—"
	}
}
