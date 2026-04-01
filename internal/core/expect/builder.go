package expect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// KeeperPath helps construct keeper paths with proper prefixes
type KeeperPath struct {
	scheme string
}

// Vault returns a builder for the vault scheme (system-level, Master Passphrase protected)
func Vault() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeVault)}
}

// Keeper returns a builder for the keeper scheme (tenant-level, password per bucket)
func Keeper() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeKeeper)}
}

// Secured returns a builder for any specific scheme
func Secured(scheme string) *KeeperPath {
	return &KeeperPath{scheme: scheme}
}

// Path constructs a full keeper path: scheme://namespace/key
func (p *KeeperPath) Path(namespace, key string) string {
	namespace = strings.TrimPrefix(namespace, "/")
	namespace = strings.TrimSuffix(namespace, "/")
	key = strings.TrimPrefix(key, "/")
	return fmt.Sprintf("%s://%s/%s", p.scheme, namespace, key)
}

// System is a convenience for vault://system/...
func (p *KeeperPath) System(key string) string {
	return p.Path("system", key)
}

// Admin is a convenience for vault://admin/...
func (p *KeeperPath) Admin(key string) string {
	return p.Path("admin", key)
}

// AdminUser returns vault://admin/users/<username>
func (p *KeeperPath) AdminUser(username string) string {
	return p.Path("admin/users", username)
}

// AdminTOTP returns vault://admin/totp/<username>
func (p *KeeperPath) AdminTOTP(username string) string {
	return p.Path("admin/totp", username)
}

// Tenant returns keeper://<tenant-name>/<key>
func (p *KeeperPath) Tenant(tenantName, key string) string {
	return p.Path(tenantName, key)
}

// Join joins multiple path parts
func (p *KeeperPath) Join(parts ...string) string {
	return p.System(filepath.Join(parts...))
}

// String returns the scheme (useful for debugging)
func (p *KeeperPath) String() string {
	return p.scheme
}

// Certs returns a builder for the certs scheme (TLS certificates, auto-unlocked)
func Certs() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeCerts)}
}

// CertLE returns certs://letsencrypt/<domain>
func (p *KeeperPath) CertLE(domain string) string {
	return p.Path("letsencrypt", domain)
}

// CertLocal returns certs://local/<domain>
func (p *KeeperPath) CertLocal(domain string) string {
	return p.Path("local", domain)
}

// CertCustom returns certs://custom/<domain>
func (p *KeeperPath) CertCustom(domain string) string {
	return p.Path("custom", domain)
}

// CertCA returns certs://ca/<filename>
func (p *KeeperPath) CertCA(filename string) string {
	return p.Path("ca", filename)
}
