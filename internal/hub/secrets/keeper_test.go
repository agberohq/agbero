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

// TestOpenStore_CreateNew verifies that OpenStore creates a new database and
// unlocks it when a passphrase is supplied.
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
		t.Error("keeper database was not created")
	}
	if store.IsLocked() {
		t.Error("store should be unlocked after OpenStore with passphrase")
	}
}

// TestOpenStore_ExistingDatabase verifies that a previously written value can
// be read back after closing and reopening the store with the same passphrase.
func TestOpenStore_ExistingDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	// First open: create store and write a value.
	store1, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("first OpenStore failed: %v", err)
	}

	// The flat Set routes to the default scheme/namespace bucket which is
	// created automatically by keeper.New — no CreateBucket call needed.
	if err := store1.Set("test-key", []byte("test-value")); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	store1.Close()

	// Second open: reopen with same passphrase and read back the value.
	store2, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("second OpenStore failed: %v", err)
	}
	defer store2.Close()

	val, err := store2.Get("test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(val) != "test-value" {
		t.Errorf("value mismatch: got %q, want %q", string(val), "test-value")
	}
}

// TestOpenStore_WrongPassphrase verifies that opening an existing database
// with the wrong passphrase returns an error.
func TestOpenStore_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logger := ll.New("test").Disable()

	// Create the store with the correct passphrase.
	cfg1 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("correct-passphrase-32-bytes!!"),
	}
	store1, err := OpenStore(dataDir, cfg1, logger)
	if err != nil {
		t.Fatalf("first OpenStore failed: %v", err)
	}
	store1.Close()

	// Attempt to reopen with a wrong passphrase.
	cfg2 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("wrong-passphrase-32-bytes!!!!"),
	}
	_, err = OpenStore(dataDir, cfg2, logger)
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

// TestOpenStore_NilCfg_ReturnsLocked verifies that passing nil cfg returns a
// locked store so the caller can prompt for and supply the passphrase.
// This is the contract required by setup/home.go::initializeKeeper.
func TestOpenStore_NilCfg_ReturnsLocked(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logger := ll.New("test").Disable()

	store, err := OpenStore(dataDir, nil, logger)
	if err != nil {
		t.Fatalf("OpenStore(nil cfg) failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Error("store should be locked when no passphrase is available — caller must unlock")
	}
}

// TestOpenStore_EmptyPassphrase_ReturnsLocked verifies that an explicitly empty
// passphrase in config also returns a locked store (caller must prompt or set env).
func TestOpenStore_EmptyPassphrase_ReturnsLocked(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logger := ll.New("test").Disable()

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value(""),
	}

	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Error("store should be locked when passphrase is empty — caller must unlock")
	}
}

// TestOpenStore_DevMode verifies that passphrase="dev" unlocks the store with a
// fixed sentinel passphrase (the KDF rejects empty passwords) and that the same
// store can be reopened consistently.
func TestOpenStore_DevMode(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logger := ll.New("test").Disable()

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("dev"),
	}

	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore (dev mode) failed: %v", err)
	}

	if store.IsLocked() {
		store.Close()
		t.Fatal("store should be unlocked in dev mode")
	}

	// Write a value, close, and reopen with the same dev passphrase.
	if err := store.Set("dev-key", []byte("dev-value")); err != nil {
		store.Close()
		t.Fatalf("Set in dev mode failed: %v", err)
	}
	store.Close()

	store2, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("second OpenStore (dev mode) failed: %v", err)
	}
	defer store2.Close()

	val, err := store2.Get("dev-key")
	if err != nil {
		t.Fatalf("Get after dev reopen failed: %v", err)
	}
	if string(val) != "dev-value" {
		t.Errorf("dev value mismatch: got %q, want %q", string(val), "dev-value")
	}
}

// TestOpenStore_WithEnvPassphrase verifies that AGBERO_PASSPHRASE is used when
// cfg carries no passphrase.
func TestOpenStore_WithEnvPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	t.Setenv("AGBERO_PASSPHRASE", "env-passphrase-32-bytes-long!!")

	cfg := &alaye.Keeper{Enabled: alaye.Active}
	logger := ll.New("test").Disable()

	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore with env passphrase failed: %v", err)
	}
	defer store.Close()

	if store.IsLocked() {
		t.Error("store should be unlocked when AGBERO_PASSPHRASE is set")
	}
}

// TestOpenStore_EnvPassphraseTakesPrecedenceOverEmpty verifies that
// AGBERO_PASSPHRASE is used even when cfg.Passphrase is empty.
func TestOpenStore_EnvPassphraseTakesPrecedenceOverEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	t.Setenv("AGBERO_PASSPHRASE", "env-passphrase-32-bytes-long!!")

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

	if store.IsLocked() {
		t.Error("store should be unlocked — AGBERO_PASSPHRASE should be used when cfg passphrase is empty")
	}
}

// TestOpenStore_CallerCanUnlockAfterLockedReturn verifies that a caller
// receiving a locked store can unlock it with the correct passphrase.
func TestOpenStore_CallerCanUnlockAfterLockedReturn(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	logger := ll.New("test").Disable()

	// First: establish the passphrase by opening with it explicitly.
	setupCfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("the-real-passphrase-32-bytes!!"),
	}
	setup, err := OpenStore(dataDir, setupCfg, logger)
	if err != nil {
		t.Fatalf("setup OpenStore failed: %v", err)
	}
	setup.Close()

	// Second: open without passphrase — caller gets a locked store.
	store, err := OpenStore(dataDir, nil, logger)
	if err != nil {
		t.Fatalf("OpenStore(nil) failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Fatal("expected locked store")
	}

	// Caller unlocks it.
	if err := store.Unlock([]byte("the-real-passphrase-32-bytes!!")); err != nil {
		t.Fatalf("caller Unlock failed: %v", err)
	}

	if store.IsLocked() {
		t.Error("store should be unlocked after caller Unlock")
	}
}

// TestKeeperPath_Builders verifies that path builder methods construct correct
// keeper URIs.
func TestKeeperPath_Builders(t *testing.T) {
	vault := expect.Vault()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"Vault.System", vault.System("test"), "vault://system/test"},
		{"Vault.Admin", vault.Admin("users"), "vault://admin/users"},
		{"Vault.AdminUser", vault.AdminUser("alice"), "vault://admin/users/alice"},
		{"Vault.AdminTOTP", vault.AdminTOTP("alice"), "vault://admin/totp/alice"},
		{"Keeper.Tenant", expect.Keeper().Tenant("mytenant", "secret"), "keeper://mytenant/secret"},
		{"Certs.CertLE", expect.Certs().CertLE("example.com"), "certs://letsencrypt/example.com"},
		{"Certs.CertLocal", expect.Certs().CertLocal("localhost"), "certs://local/localhost"},
		{"Certs.CertCustom", expect.Certs().CertCustom("custom.com"), "certs://custom/custom.com"},
		{"Certs.CertCA", expect.Certs().CertCA("root"), "certs://ca/root"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// TestOpenStore_CreatesBucketAndReadsBack verifies the full round-trip with an
// explicit bucket creation and namespaced read.
func TestOpenStore_CreatesBucketAndReadsBack(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	store, err := OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create an explicit LevelPasswordOnly bucket in the vault scheme.
	if err := store.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "test"); err != nil {
		// ErrPolicyImmutable is fine — bucket may already exist on re-runs.
		if err.Error() != "policy already exists for this bucket" {
			t.Fatalf("CreateBucket failed: %v", err)
		}
	}

	// Write via namespaced full and read back via the flat Get convenience.
	if err := store.SetNamespacedFull("vault", "system", "jwt_secret", []byte("s3cr3t")); err != nil {
		t.Fatalf("SetNamespacedFull failed: %v", err)
	}

	val, err := store.Get("vault://system/jwt_secret")
	if err != nil {
		t.Fatalf("Get via URI failed: %v", err)
	}
	if string(val) != "s3cr3t" {
		t.Errorf("got %q, want %q", string(val), "s3cr3t")
	}
}

// containsError reports whether err contains the target substring.
func containsError(err error, target string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), target)
}
