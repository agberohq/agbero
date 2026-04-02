package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
)

// TestOpenStore_CreateNew verifies that OpenStore creates a new database and unlocks it with passphrase
func TestOpenStore_CreateNew(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		AutoLock:   alaye.Duration(5 * time.Minute),
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()
	dbPath := filepath.Join(dataDir, woos.DefaultKeeperName)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Keeper database was not created")
	}
	if store.IsLocked() {
		t.Error("Store should be unlocked")
	}
}

// TestOpenStore_ExistingDatabase verifies that an existing database can be reopened with correct passphrase
func TestOpenStore_ExistingDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store1, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("First OpenStore failed: %v", err)
	}

	// Create a bucket first
	if err := store1.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	if err := store1.Set("test-key", []byte("test-value")); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	store1.Close()

	store2, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("Second OpenStore failed: %v", err)
	}
	defer store2.Close()

	val, err := store2.Get("test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(val) != "test-value" {
		t.Errorf("Value mismatch: got %s, want test-value", val)
	}
}

// TestOpenStore_WrongPassphrase verifies that opening with incorrect passphrase fails
func TestOpenStore_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg1 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("correct-passphrase-32-bytes!!"),
	}
	logger := ll.New("test").Disable()
	store1, err := OpenStore(dataDir, cfg1, logger)
	if err != nil {
		t.Fatalf("First OpenStore failed: %v", err)
	}
	store1.Close()

	cfg2 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("wrong-passphrase-32-bytes!!!"),
	}
	_, err = OpenStore(dataDir, cfg2, logger)
	if err == nil {
		t.Fatal("Expected error with wrong passphrase, got nil")
	}
}

// TestOpenStore_NoPassphrase verifies store behavior when no passphrase is provided
func TestOpenStore_NoPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value(""),
	}
	logger := ll.New("test").Disable()
	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// With empty passphrase, the store should be unlocked (development mode)
	if store.IsLocked() {
		t.Error("Store should not be locked when created with empty passphrase")
	}

	// Verify we can write to the store
	if err := store.Set("test-key", []byte("test-value")); err != nil {
		t.Errorf("Should be able to write to store with empty passphrase: %v", err)
	}
}

// TestOpenStore_WithEnvPassphrase verifies that AGBERO_PASSPHRASE env var is used when config lacks passphrase
func TestOpenStore_WithEnvPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	os.Setenv("AGBERO_PASSPHRASE", "env-passphrase-32-bytes-long!!")
	defer os.Unsetenv("AGBERO_PASSPHRASE")
	cfg := &alaye.Keeper{
		Enabled: alaye.Active,
	}
	logger := ll.New("test").Disable()
	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore with env passphrase failed: %v", err)
	}
	defer store.Close()
	if store.IsLocked() {
		t.Error("Store should be unlocked with env passphrase")
	}
}

// TestKeeperPath_Builders verifies that path builder methods construct correct keeper URIs
func TestKeeperPath_Builders(t *testing.T) {
	vault := expect.Vault()
	if vault.System("test") != "vault://system/test" {
		t.Errorf("System path: got %s", vault.System("test"))
	}
	if vault.Admin("users") != "vault://admin/users" {
		t.Errorf("Admin path: got %s", vault.Admin("users"))
	}
	if vault.AdminUser("alice") != "vault://admin/users/alice" {
		t.Errorf("AdminUser path: got %s", vault.AdminUser("alice"))
	}
	keeper := expect.Keeper()
	if keeper.Tenant("mytenant", "secret") != "keeper://mytenant/secret" {
		t.Errorf("Tenant path: got %s", keeper.Tenant("mytenant", "secret"))
	}
	certs := expect.Certs()
	if certs.CertLE("example.com") != "certs://letsencrypt/example.com" {
		t.Errorf("CertLE path: got %s", certs.CertLE("example.com"))
	}
	if certs.CertLocal("localhost") != "certs://local/localhost" {
		t.Errorf("CertLocal path: got %s", certs.CertLocal("localhost"))
	}
	if certs.CertCustom("custom.com") != "certs://custom/custom.com" {
		t.Errorf("CertCustom path: got %s", certs.CertCustom("custom.com"))
	}
	if certs.CertCA("root") != "certs://ca/root" {
		t.Errorf("CertCA path: got %s", certs.CertCA("root"))
	}
}

// Helper function to check if error contains a specific string
func containsError(err error, target string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), target)
}
