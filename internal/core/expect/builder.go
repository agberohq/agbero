package expect

import (
	"fmt"
	"strings"
)

// KeeperPath builds keeper URIs.
//
// # Bucket structure
//
// keeper's parseKeyExtended splits a URI on the FIRST "/" after the scheme.
// That means the FIRST path segment is the bucket namespace, and everything
// after the second "/" is the key — regardless of how many segments the
// builder puts in the "namespace" argument.
//
//	vault://admin/users/alice  →  bucket=vault:admin   key=users/alice
//	vault://admin/totp/alice   →  bucket=vault:admin   key=totp/alice
//	vault://key/internal       →  bucket=vault:key     key=internal
//	vault://temp/setup         →  bucket=vault:temp    key=setup
//
// Practical consequence: ALL vault://admin/* keys share one bucket (vault:admin).
// CreateBucket("vault", "admin", LevelPasswordOnly, ...) is the only call needed
// for any admin-scoped key. See VaultBuckets for the full list.
type KeeperPath struct {
	scheme string
}

// VaultBuckets lists every bucket namespace that must be created for the vault
// scheme. Call CreateBucket("vault", ns, LevelPasswordOnly, ...) for each one
// after the store is unlocked.
var VaultBuckets = []string{"admin", "key", "temp"}

// Vault returns a builder for the vault scheme.
// vault:// is the agbero-internal scheme — it holds admin users, JWT secrets,
// the internal auth key, cluster secret, and TOTP secrets.
// User-supplied secrets should use SS() instead.
func Vault() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeVault)}
}

// SS returns a builder for the ss:// scheme (user-space secrets).
// ss:// is the public scheme exposed through the keeper API.
// store.Set strips the scheme prefix via WithoutScheme() before writing, so
// all ss:// keys land in the "default" keeper scheme.
func SS() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeSS)}
}

// Keeper returns a builder for the keeper:// scheme (tenant-level).
func Keeper() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeKeeper)}
}

// Certs returns a builder for the certs:// scheme (TLS certificates).
func Certs() *KeeperPath {
	return &KeeperPath{scheme: string(SchemeCerts)}
}

// Secured returns a builder for an arbitrary scheme.
func Secured(scheme string) *KeeperPath {
	return &KeeperPath{scheme: scheme}
}

// Path constructs a full URI: scheme://namespace/key
//
// Important: keeper only uses the FIRST segment of namespace as the bucket.
// "admin/users" and "admin/totp" both map to bucket "admin"; the sub-segment
// becomes part of the key. This is intentional — all vault://admin/* keys
// share one LevelPasswordOnly bucket.
func (p *KeeperPath) Path(namespace, key string) string {
	namespace = strings.TrimPrefix(namespace, "/")
	namespace = strings.TrimSuffix(namespace, "/")
	key = strings.TrimPrefix(key, "/")
	return fmt.Sprintf("%s://%s/%s", p.scheme, namespace, key)
}

// Namespace returns the real keeper bucket namespace for the given path segment.
// This is always the first "/" segment, matching parseKeyExtended's behaviour.
func (p *KeeperPath) Namespace(segment string) string {
	return strings.SplitN(strings.TrimPrefix(segment, "/"), "/", 2)[0]
}

// vault:// convenience methods
// All of these share bucket vault:admin or vault:key or vault:temp.
// One CreateBucket call per bucket namespace is sufficient.

// Admin returns vault://admin/<key>. Bucket: vault:admin.
func (p *KeeperPath) Admin(key string) string {
	return p.Path("admin", key)
}

// AdminUser returns vault://admin/users/<username>. Bucket: vault:admin, key: users/<username>.
func (p *KeeperPath) AdminUser(username string) string {
	return p.Path("admin", "users/"+username)
}

// AdminTOTP returns vault://admin/totp/<username>. Bucket: vault:admin, key: totp/<username>.
func (p *KeeperPath) AdminTOTP(username string) string {
	return p.Path("admin", "totp/"+username)
}

// AdminJWT returns vault://admin/jwt/<username>. Bucket: vault:admin, key: jwt/<username>.
// Note: previously this emitted "admin/jtt" — that was a typo; the correct value is "jwt".
func (p *KeeperPath) AdminJWT(username string) string {
	return p.Path("admin", "jwt/"+username)
}

// Key returns vault://key/<key>. Bucket: vault:key.
// Used for system keys: "internal" (PPK), "cluster" (gossip secret).
func (p *KeeperPath) Key(key string) string {
	return p.Path("key", key)
}

// Temp returns vault://temp/<key>. Bucket: vault:temp.
// Used for transient setup state.
func (p *KeeperPath) Temp(key string) string {
	return p.Path("temp", key)
}

// System returns vault://system/<key>. Bucket: vault:system.
func (p *KeeperPath) System(key string) string {
	return p.Path("system", key)
}

// certs:// convenience methods

// CertLE returns certs://letsencrypt/<domain>.
func (p *KeeperPath) CertLE(domain string) string {
	return p.Path("letsencrypt", domain)
}

// CertLocal returns certs://local/<domain>.
func (p *KeeperPath) CertLocal(domain string) string {
	return p.Path("local", domain)
}

// CertCustom returns certs://custom/<domain>.
func (p *KeeperPath) CertCustom(domain string) string {
	return p.Path("custom", domain)
}

// CertCA returns certs://ca/<filename>.
func (p *KeeperPath) CertCA(filename string) string {
	return p.Path("ca", filename)
}

// keeper:// convenience methods

// Tenant returns keeper://<tenantName>/<key>.
func (p *KeeperPath) Tenant(tenantName, key string) string {
	return p.Path(tenantName, key)
}

// String returns the scheme string.
func (p *KeeperPath) String() string {
	return p.scheme
}
