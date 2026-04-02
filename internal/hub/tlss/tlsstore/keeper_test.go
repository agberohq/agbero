package tlsstore

import (
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/keeper"
)

// setupTestKeeper creates a temporary Keeper instance for testing
func setupTestKeeper(t testing.TB) (*keeper.Keeper, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test-keeper.db")

	// Create test configuration
	config := keeper.Config{
		DBPath:           dbPath,
		EnableAudit:      true,
		AutoLockInterval: 0, // Never auto-lock for tests
	}

	// Create new database
	store, err := keeper.New(config)
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}

	// Generate a test passphrase
	passphrase := "test-passphrase-32-bytes-long!!"
	passBytes := []byte(passphrase)

	// Unlock the store
	if err := store.Unlock(passBytes); err != nil {
		store.Close()
		t.Fatalf("Failed to unlock keeper: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		store.Close()
	}

	return store, cleanup
}

// setupTestKeeperWithCipher creates a Keeper with security cipher for encrypted storage
func setupTestKeeperWithCipher(t testing.TB) (*keeper.Keeper, *security.Cipher, func()) {
	t.Helper()

	store, cleanup := setupTestKeeper(t)

	// Create cipher for encryption testing
	cipher, err := security.NewCipher("test-cipher-key-32-bytes-long-!!!!!!")
	if err != nil {
		cleanup()
		t.Fatalf("Failed to create cipher: %v", err)
	}

	return store, cipher, cleanup
}

func TestKeeperStorage_BasicSaveLoad(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Test data
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----")
	domain := "example.com"

	// Save certificate
	if err := keeperStore.Save(IssuerACME, domain, certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load certificate
	loadedCert, loadedKey, err := keeperStore.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify
	if string(loadedCert) != string(certPEM) {
		t.Errorf("Cert mismatch: got %q, want %q", loadedCert, certPEM)
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("Key mismatch: got %q, want %q", loadedKey, keyPEM)
	}
}

func TestKeeperStorage_SaveWithDifferentIssuers(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	domain := "test.com"
	customCert := []byte("custom-cert")
	customKey := []byte("custom-key")
	acmeCert := []byte("acme-cert")
	acmeKey := []byte("acme-key")
	localCert := []byte("local-cert")
	localKey := []byte("local-key")

	// Save under different issuers
	if err := keeperStore.Save(IssuerCustom, domain, customCert, customKey); err != nil {
		t.Fatalf("Save custom failed: %v", err)
	}
	if err := keeperStore.Save(IssuerACME, domain, acmeCert, acmeKey); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}
	if err := keeperStore.Save(IssuerLocal, domain, localCert, localKey); err != nil {
		t.Fatalf("Save local failed: %v", err)
	}

	// Load should return custom (highest priority)
	cert, key, err := keeperStore.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(cert) != string(customCert) {
		t.Errorf("Expected custom cert, got %s", cert)
	}
	if string(key) != string(customKey) {
		t.Errorf("Expected custom key, got %s", key)
	}
}

func TestKeeperStorage_LoadPriority(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	domain := "priority.com"

	// Save only under ACME (lower priority)
	acmeCert := []byte("acme-cert")
	acmeKey := []byte("acme-key")

	if err := keeperStore.Save(IssuerACME, domain, acmeCert, acmeKey); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}

	// Load should return ACME (since custom doesn't exist)
	cert, key, err := keeperStore.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(cert) != string(acmeCert) {
		t.Errorf("Expected ACME cert, got %s", cert)
	}
	if string(key) != string(acmeKey) {
		t.Errorf("Expected ACME key, got %s", key)
	}

	// Now add custom (higher priority)
	customCert := []byte("custom-cert")
	customKey := []byte("custom-key")

	if err := keeperStore.Save(IssuerCustom, domain, customCert, customKey); err != nil {
		t.Fatalf("Save custom failed: %v", err)
	}

	// Load should now return custom
	cert, key, err = keeperStore.Load(domain)
	if err != nil {
		t.Fatalf("Load after custom save failed: %v", err)
	}

	if string(cert) != string(customCert) {
		t.Errorf("Expected custom cert after save, got %s", cert)
	}
	if string(key) != string(customKey) {
		t.Errorf("Expected custom key after save, got %s", key)
	}
}

func TestKeeperStorage_SystemAndCA(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Save CA certificate
	caCert := []byte("ca-certificate-data")
	caKey := []byte("ca-private-key")

	if err := keeperStore.Save(IssuerCA, "ca", caCert, caKey); err != nil {
		t.Fatalf("Save CA failed: %v", err)
	}

	// Save system key (ACME account)
	systemKey := []byte("acme-account-private-key")

	if err := keeperStore.Save(IssuerSystem, "acme_account", nil, systemKey); err != nil {
		t.Fatalf("Save system key failed: %v", err)
	}

	// Load CA
	loadedCert, loadedKey, err := keeperStore.Load("ca")
	if err != nil {
		t.Fatalf("Load CA failed: %v", err)
	}

	if string(loadedCert) != string(caCert) {
		t.Errorf("CA cert mismatch")
	}
	if string(loadedKey) != string(caKey) {
		t.Errorf("CA key mismatch")
	}

	// Load system key (should work even without cert)
	_, loadedSysKey, err := keeperStore.Load("acme_account")
	if err != nil {
		t.Fatalf("Load system key failed: %v", err)
	}

	if string(loadedSysKey) != string(systemKey) {
		t.Errorf("System key mismatch")
	}
}

func TestKeeperStorage_List(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	domains := []string{"a.com", "b.com", "c.com", "*.wildcard.com"}

	for _, domain := range domains {
		if err := keeperStore.Save(IssuerCustom, domain, []byte("cert"), []byte("key")); err != nil {
			t.Fatalf("Save %s failed: %v", domain, err)
		}
	}

	// Add some ACME certs
	if err := keeperStore.Save(IssuerACME, "d.com", []byte("acme-cert"), []byte("acme-key")); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}

	list, err := keeperStore.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	// Should have all 5 domains (4 custom + 1 ACME)
	if len(list) != 5 {
		t.Errorf("Expected 5 domains, got %d: %v", len(list), list)
	}

	// Check wildcard conversion
	found := false
	for _, d := range list {
		if d == "*.wildcard.com" {
			found = true
		}
	}
	if !found {
		t.Error("Wildcard domain not properly preserved")
	}
}

func TestKeeperStorage_Delete(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Save multiple certificates
	domain := "delete-me.com"

	if err := keeperStore.Save(IssuerCustom, domain, []byte("custom-cert"), []byte("custom-key")); err != nil {
		t.Fatalf("Save custom failed: %v", err)
	}
	if err := keeperStore.Save(IssuerACME, domain, []byte("acme-cert"), []byte("acme-key")); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}

	// Verify it exists
	_, _, err = keeperStore.Load(domain)
	if err != nil {
		t.Fatalf("Load before delete failed: %v", err)
	}

	// Delete
	if err := keeperStore.Delete(domain); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	_, _, err = keeperStore.Load(domain)
	if err != ErrCertNotFound {
		t.Errorf("Expected ErrCertNotFound after delete, got %v", err)
	}

	// Other domains should still work
	if err := keeperStore.Save(IssuerLocal, "other.com", []byte("other"), []byte("other-key")); err != nil {
		t.Fatalf("Save other domain failed: %v", err)
	}
}

func TestKeeperStorage_EmptyKey(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Save with empty key (should work for system keys)
	if err := keeperStore.Save(IssuerSystem, "empty-key-test", nil, []byte("key-only")); err != nil {
		t.Fatalf("Save with empty cert failed: %v", err)
	}

	// Load should work
	_, key, err := keeperStore.Load("empty-key-test")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(key) != "key-only" {
		t.Errorf("Key mismatch: got %s, want key-only", key)
	}
}

func TestKeeperStorage_NotFound(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Load non-existent domain
	_, _, err = keeperStore.Load("does-not-exist.com")
	if err != ErrCertNotFound {
		t.Errorf("Expected ErrCertNotFound, got %v", err)
	}
}

func TestKeeperStorage_MultipleNamespaces(t *testing.T) {
	store, cleanup := setupTestKeeper(t)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		t.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Store same domain in different namespaces
	domain := "multi.com"

	// Save in custom
	if err := keeperStore.Save(IssuerCustom, domain, []byte("custom"), []byte("custom-key")); err != nil {
		t.Fatalf("Save custom failed: %v", err)
	}

	// Verify we can read it directly via different issuer (not through Load)
	// This tests the underlying Keeper storage directly

	// Read via Keeper directly to verify it's in the correct namespace
	_, err = store.GetNamespacedFull("certs", IssuerCustom, domain+".crt")
	if err != nil {
		t.Errorf("Certificate not found in custom namespace: %v", err)
	}

	// It should NOT be in ACME namespace
	_, err = store.GetNamespacedFull("certs", IssuerACME, domain+".crt")
	if err == nil {
		t.Error("Certificate found in ACME namespace when it shouldn't be")
	}
}

// Benchmark tests
func BenchmarkKeeperStorage_Save(b *testing.B) {
	store, cleanup := setupTestKeeper(b)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		b.Fatalf("Failed to create KeeperStore: %v", err)
	}

	certPEM := []byte("bench-cert")
	keyPEM := []byte("bench-key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := "bench" + string(rune(i)) + ".com"
		if err := keeperStore.Save(IssuerCustom, domain, certPEM, keyPEM); err != nil {
			b.Fatalf("Save failed: %v", err)
		}
	}
}

func BenchmarkKeeperStorage_Load(b *testing.B) {
	store, cleanup := setupTestKeeper(b)
	defer cleanup()

	keeperStore, err := NewKeeper(store)
	if err != nil {
		b.Fatalf("Failed to create KeeperStore: %v", err)
	}

	// Pre-populate
	certPEM := []byte("bench-cert")
	keyPEM := []byte("bench-key")
	domain := "bench.com"

	if err := keeperStore.Save(IssuerCustom, domain, certPEM, keyPEM); err != nil {
		b.Fatalf("Pre-populate failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := keeperStore.Load(domain)
		if err != nil {
			b.Fatalf("Load failed: %v", err)
		}
	}
}
