package helper

import (
	"os"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/dustin/go-humanize"
)

type Cert struct {
	p *Helper
}

// newLocal builds a tlss.Local for CLI certificate operations (CA install,
// uninstall, list). These operations manage the local development CA and are
// disk-based by design: the CA must be accessible without keeper so that
// agbero cert install can be run before keeper is configured.
//
// In ephemeral mode (serve/proxy) there is no keeper and this is always correct.
// In full server mode the server's tlsstore (keeper-backed when keeper is
// configured) handles cert management; cert CLI is for local CA trust only.
func (c *Cert) newLocal(configPath string) (certsDir expect.Folder, loc *tlss.Local) {
	if global, err := loadGlobal(configPath); err == nil && global.Storage.CertsDir != "" {
		certsDir = global.Storage.CertsDir
	}
	store := newDiskStore(certsDir)
	loc = tlss.NewLocal(c.p.Logger, store)
	return certsDir, loc
}

// newDiskStore creates a tlsstore.Disk for the given certsDir.
// On error or empty certsDir, falls back to memory so that read operations
// on ephemeral/unconfigured installs still work gracefully.
func newDiskStore(certsDir expect.Folder) tlsstore.Store {
	if certsDir != "" {
		ds, err := tlsstore.NewDisk(tlsstore.DiskConfig{CertDir: certsDir})
		if err == nil {
			return ds
		}
	}
	return tlsstore.NewMemory()
}

func (c *Cert) Install(configPath string, force bool) {
	_, loc := c.newLocal(configPath)

	if force {
		c.p.Logger.Info("Force flag detected. Removing existing CA and regenerating...")
		_ = loc.UninstallCARoot()
		loc.RemoveCA()
	}

	// InstallCARootIfNeeded is idempotent — safe to call unconditionally.
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

	// Clean up remaining PEM/key/crt files from the cert root directory.
	files, err := certsDir.ReadFiles()
	if err != nil {
		c.p.Logger.Warnf("could not read dir: %v", err)
		return
	}

	count := 0
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".crt") {
			if err := os.Remove(certsDir.FilePath(name)); err == nil {
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

	storageDir := global.Storage.CertsDir
	u := ui.New()
	u.SectionHeader("Certificate store")
	u.KeyValue("Directory", storageDir.Path())

	if !storageDir.ExistsAbsolute() {
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
