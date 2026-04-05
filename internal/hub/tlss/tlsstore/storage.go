package tlsstore

import (
	"errors"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/keeper"
)

var ErrCertNotFound = errors.New("certificate not found")

const (
	IssuerCustom = "custom"
	IssuerACME   = "letsencrypt"
	IssuerLocal  = "local"
	IssuerCA     = "ca"
	IssuerSystem = "system" // For ACME account keys, etc.
)

type Store interface {
	// Save stores a certificate and key under a specific issuer namespace
	Save(issuer, domain string, certPEM, keyPEM []byte) error

	// Load searches across issuers (Custom -> ACME -> Local) to find the certificate
	Load(domain string) (certPEM, keyPEM []byte, err error)

	// List returns all domains across all issuers
	List() ([]string, error)

	// Delete removes the domain from ALL issuer namespaces
	Delete(domain string) error
}

// Config holds configuration for storage backends
type Config struct {
	// For disk storage
	DataDir string           // For CA and System certs (persistent, secure)
	CertDir string           // For domain certs (can be ephemeral)
	Cipher  *security.Cipher // Use concrete type, not interface{}

	// For Keeper storage
	Keeper *keeper.Keeper // Use concrete type, not interface{}
}

// New creates the appropriate storage backend based on configuration
func New(cfg Config) (Store, error) {
	// Priority: Keeper > Disk > Memory

	// Try Keeper first (if available)
	if cfg.Keeper != nil {
		return NewKeeper(cfg.Keeper)
	}

	// Try Disk storage if directories are configured
	if cfg.DataDir != "" || cfg.CertDir != "" {
		return NewDisk(DiskConfig{
			DataDir: cfg.DataDir,
			CertDir: cfg.CertDir,
			Cipher:  cfg.Cipher,
		})
	}

	// Fallback to memory
	return NewMemory(), nil
}
