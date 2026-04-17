package helper

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"runtime"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/hub/tlss/tlsstore"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/dustin/go-humanize"
)

type Cert struct {
	p *Helper
}

// newStore returns a tlsstore.Store backed by the keeper when one is injected
// into the Helper, falling back to a disk-backed store from the config file.
// This ensures cert CLI commands always work against the same backend as the
// running server regardless of whether certs are stored in keeper or on disk.
func (c *Cert) newStore(configPath string) (tlsstore.Store, expect.Folder) {
	var certsDir expect.Folder
	var dataDir expect.Folder

	if global, err := loadGlobal(configPath); err == nil {
		certsDir = global.Storage.CertsDir
		dataDir = global.Storage.DataDir
	}

	if c.p.Store != nil {
		store, err := tlsstore.NewKeeper(c.p.Store)
		if err == nil {
			return store, certsDir
		}
		c.p.Logger.Warnf("failed to create keeper TLS store, falling back to disk: %v", err)
	}

	store, err := tlsstore.NewDisk(tlsstore.DiskConfig{
		DataDir: dataDir,
		CertDir: certsDir,
	})
	if err == nil {
		return store, certsDir
	}
	return tlsstore.NewMemory(), certsDir
}

// newLocal returns a tlss.Local backed by the correct store (keeper or disk).
func (c *Cert) newLocal(configPath string) *tlss.Local {
	store, _ := c.newStore(configPath)
	return tlss.NewLocal(c.p.Logger, store)
}

// Install installs the local CA certificate into the system trust store.
// Pass force=true to remove and reinstall even when a CA already exists.
func (c *Cert) Install(configPath string, force bool) {
	loc := c.newLocal(configPath)

	if force {
		c.p.Logger.Info("force flag: removing existing CA before reinstall")
		_ = loc.UninstallCARoot()
		loc.RemoveCA()
	}

	if err := loc.InstallCARootIfNeeded(); err != nil {
		c.p.Logger.Fatal("failed to install CA: ", err)
	}
	c.p.Logger.Info("CA root installed successfully")
	c.printNSSHint(loc)
}

func (c *Cert) printNSSHint(loc *tlss.Local) {
	if loc.HasCertutil() {
		return
	}
	switch runtime.GOOS {
	case def.Darwin:
		c.p.Logger.Warn(def.NSSInstallHintDarwin)
	case def.Linux:
		c.p.Logger.Warn(def.NSSInstallHintLinux)
	default:
		c.p.Logger.Warn(def.NSSInstallHintOther)
	}
}

// Uninstall removes the CA from the system trust store and deletes the CA
// certificate data from the active store (keeper or disk).
func (c *Cert) Uninstall(configPath string) {
	loc := c.newLocal(configPath)

	c.p.Logger.Info("removing CA from system trust store")
	if err := loc.UninstallCARoot(); err != nil {
		c.p.Logger.Warnf("system trust store cleanup: %v (may already be removed)", err)
	} else {
		c.p.Logger.Info("CA removed from system trust store")
	}

	loc.RemoveCA()
	c.p.Logger.Info("CA certificate removed from store")
}

// Delete removes a single domain's certificate from the active store.
func (c *Cert) Delete(configPath, domain string) {
	if domain == "" {
		c.p.Logger.Fatal("domain is required")
	}
	store, _ := c.newStore(configPath)
	if err := store.Delete(domain); err != nil {
		c.p.Logger.Fatal("failed to delete certificate for ", domain, ": ", err)
	}
	u := ui.New()
	u.Render(func() {
		u.SuccessLine(fmt.Sprintf("certificate for %q deleted from store", domain))
	})
}

// List prints all certificates held in the active store.
func (c *Cert) List(configPath string) {
	loc := c.newLocal(configPath)
	certs, err := loc.ListCertificates()
	if err != nil {
		c.p.Logger.Fatal("failed to list certificates: ", err)
	}

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("Certificates")
	})

	if len(certs) == 0 {
		u.Render(func() { u.WarnLine("no certificates found") })
		return
	}

	var rows [][]string
	for _, name := range certs {
		domain, kind := parseCertName(name)
		rows = append(rows, []string{domain, kind, name})
	}
	u.Render(func() {
		u.Table([]string{"Domain", "Type", "Key"}, rows)
	})
}

// Info shows details about each certificate in the active store including
// the backend type, expiry date, and issuer.
func (c *Cert) Info(configPath string) {
	store, certsDir := c.newStore(configPath)

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("Certificate store")
		if c.p.Store != nil {
			u.KeyValue("Backend", "keeper (encrypted)")
		} else {
			u.KeyValue("Backend", "disk")
			u.KeyValue("Directory", certsDir.Path())
		}
	})

	domains, err := store.List()
	if err != nil {
		u.Render(func() { u.ErrorHint("cannot read store", err.Error()) })
		return
	}

	if len(domains) == 0 {
		u.Render(func() { u.WarnLine("no certificates found") })
		return
	}

	var rows [][]string
	for _, domain := range domains {
		certPEM, _, loadErr := store.Load(domain)
		if loadErr != nil || len(certPEM) == 0 {
			rows = append(rows, []string{domain, "—", "—", "unreadable"})
			continue
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			rows = append(rows, []string{domain, "—", "—", "invalid PEM"})
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			rows = append(rows, []string{domain, "—", "—", "parse error"})
			continue
		}
		size := humanize.Bytes(uint64(len(certPEM)))
		expiry := cert.NotAfter.Format("2006-01-02")
		rows = append(rows, []string{domain, size, expiry, cert.Issuer.CommonName})
	}

	u.Render(func() {
		u.Table([]string{"Domain", "Size", "Expires", "Issuer"}, rows)
	})
}

func parseCertName(name string) (domain, kind string) {
	switch {
	case name == def.InternalAuthKeyName:
		return "internal", "auth key"
	default:
		return name, "—"
	}
}
