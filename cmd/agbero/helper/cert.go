package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/tlss"
	"github.com/dustin/go-humanize"
)

type Cert struct {
	p *Helper
}

// Install installs the local CA root, then prints an NSS hint when certutil is absent.
// Firefox and Chrome require certutil to trust the CA; we surface the install command per OS.
func (c *Cert) Install(configPath string, force bool) {
	loc := c.newLocal(configPath)
	if tlss.IsCARootInstalled(loc.CertDir.Path()) && !force {
		c.p.Logger.Info("CA root is already installed. Use --force to reinstall.")
		return
	}
	if err := loc.InstallCARootIfNeeded(); err != nil {
		c.p.Logger.Fatal("failed to install CA: ", err)
	}
	c.p.Logger.Info("CA root installed successfully.")
	c.printNSSHint(loc)
}

// printNSSHint warns the user when NSS certutil is missing and provides
// the OS-specific install command so Firefox/Chrome trust store is updated.
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
	loc := c.newLocal(configPath)
	c.p.Logger.Info("uninstalling CA...")
	if err := loc.UninstallCARoot(); err != nil {
		c.p.Logger.Warnf("system trust store cleanup: %v (might already be removed)", err)
	} else {
		c.p.Logger.Info("removed CA from system trust store")
	}

	dir := loc.CertDir.Path()
	files, err := os.ReadDir(dir)
	if err != nil {
		c.p.Logger.Warnf("could not read dir: %v", err)
		return
	}

	count := 0
	for _, f := range files {
		name := f.Name()
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".crt") {
			if err := os.Remove(filepath.Join(dir, name)); err == nil {
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
	loc := c.newLocal(configPath)
	certs, err := loc.ListCertificates()
	if err != nil {
		c.p.Logger.Fatal("failed to list certificates: ", err)
	}
	if len(certs) == 0 {
		c.p.Logger.Warn("no certificates found")
		return
	}
	c.p.Logger.Infof("found %d certificates:", len(certs))
	for i, cert := range certs {
		c.p.Logger.Printf("  %d. %s\n", i+1, cert)
	}
}

func (c *Cert) Info(configPath string) {
	global, err := loadGlobal(configPath)
	if err != nil {
		c.p.Logger.Warnf("could not load config: %v", err)
		return
	}
	storageDir := woos.NewFolder(global.Storage.CertsDir)
	fmt.Println("\nCERTIFICATE INFORMATION")
	fmt.Printf("Store Listing: %s\n", storageDir.Path())
	if !storageDir.Exists("") {
		fmt.Println("⚠  store does not exist")
		return
	}
	files, err := storageDir.ReadFiles()
	if err != nil {
		fmt.Printf("⚠  cannot read directory: %v\n", err)
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
		fmt.Println("  (no certificates found)")
	}
}

func (c *Cert) newLocal(configPath string) *tlss.Local {
	loc := tlss.NewLocal(c.p.Logger)
	if global, err := loadGlobal(configPath); err == nil && global.Storage.CertsDir != "" {
		_ = loc.SetStorageDir(woos.NewFolder(global.Storage.CertsDir))
	}
	return loc
}
