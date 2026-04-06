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

// TestOpen_CreateNew verifies that Open creates a new database and
// unlocks it when a passphrase is supplied.
func TestOpen_CreateNew(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		AutoLock:   alaye.Duration(5 * time.Minute),
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	dbPath := filepath.Join(dataDir.Path(), woos.DefaultKeeperName)
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("keeper database was not created")
	}
	if store.IsLocked() {
		t.Error("store should be unlocked after Open with passphrase")
	}
}

// TestOpen_ExistingDatabase verifies that a previously written value can
// be read back after closing and reopening the store with the same passphrase.
func TestOpen_ExistingDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	// First open: create store and write a value.
	store1, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}

	// The flat Set routes to the default scheme/namespace bucket which is
	// created automatically by keeper.New — no CreateBucket call needed.
	if err := store1.Set("test-key", []byte("test-value")); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	store1.Close()

	// Second open: reopen with same passphrase and read back the value.
	store2, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("second Open failed: %v", err)
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

// TestOpen_WrongPassphrase verifies that opening an existing database
// with the wrong passphrase returns an error.
func TestOpen_WrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	// Create the store with the correct passphrase.
	cfg1 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("correct-passphrase-32-bytes!!"),
	}
	store1, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg1,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("first Open failed: %v", err)
	}
	store1.Close()

	// Attempt to reopen with a wrong passphrase.
	cfg2 := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("wrong-passphrase-32-bytes!!!!"),
	}
	_, err = Open(Config{
		DataDir:     dataDir,
		Setting:     cfg2,
		Logger:      logger,
		Interactive: false,
	})
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
}

// TestOpen_NilCfg_ReturnsLocked verifies that passing nil cfg returns a
// locked store so the caller can prompt for and supply the passphrase.
// This is the contract required by setup/home.go::initializeKeeper.
func TestOpen_NilCfg_ReturnsLocked(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     nil,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open(nil cfg) failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Error("store should be locked when no passphrase is available — caller must unlock")
	}
}

// TestOpen_EmptyPassphrase_ReturnsLocked verifies that an explicitly empty
// passphrase in config also returns a locked store (caller must prompt or set env).
func TestOpen_EmptyPassphrase_ReturnsLocked(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value(""),
	}

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Error("store should be locked when passphrase is empty — caller must unlock")
	}
}

// TestOpen_DevMode verifies that passphrase="dev" unlocks the store with a
// sentinel passphrase (the KDF rejects empty passwords) and that the same
// store can be reopened consistently.
func TestOpen_DevMode(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("dev"),
	}

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open (dev mode) failed: %v", err)
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

	store2, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("second Open (dev mode) failed: %v", err)
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

// TestOpen_WithEnvPassphrase verifies that AGBERO_PASSPHRASE is used when
// cfg carries no passphrase.
func TestOpen_WithEnvPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	t.Setenv("AGBERO_PASSPHRASE", "env-passphrase-32-bytes-long!!")

	cfg := &alaye.Keeper{Enabled: alaye.Active}
	logger := ll.New("test").Disable()

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open with env passphrase failed: %v", err)
	}
	defer store.Close()

	if store.IsLocked() {
		t.Error("store should be unlocked when AGBERO_PASSPHRASE is set")
	}
}

// TestOpen_EnvPassphraseTakesPrecedenceOverEmpty verifies that
// AGBERO_PASSPHRASE is used even when cfg.Passphrase is empty.
func TestOpen_EnvPassphraseTakesPrecedenceOverEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	t.Setenv("AGBERO_PASSPHRASE", "env-passphrase-32-bytes-long!!")

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value(""),
	}
	logger := ll.New("test").Disable()

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer store.Close()

	if store.IsLocked() {
		t.Error("store should be unlocked — AGBERO_PASSPHRASE should be used when cfg passphrase is empty")
	}
}

// TestOpen_CallerCanUnlockAfterLockedReturn verifies that a caller
// receiving a locked store can unlock it with the correct passphrase.
func TestOpen_CallerCanUnlockAfterLockedReturn(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	// First: establish the passphrase by opening with it explicitly.
	setupCfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("the-real-passphrase-32-bytes!!"),
	}
	setup, err := Open(Config{
		DataDir:     dataDir,
		Setting:     setupCfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("setup Open failed: %v", err)
	}
	setup.Close()

	// Second: open without passphrase — caller gets a locked store.
	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     nil,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open(nil) failed: %v", err)
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

// TestMustOpen_Success verifies MustOpen returns unlocked store.
func TestMustOpen_Success(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	store, err := MustOpen(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("MustOpen failed: %v", err)
	}
	defer store.Close()

	if store.IsLocked() {
		t.Error("MustOpen should return unlocked store")
	}
}

// TestMustOpen_LockedReturnsError verifies MustOpen returns error when locked.
func TestMustOpen_LockedReturnsError(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	logger := ll.New("test").Disable()

	// Create a locked store by opening with nil config
	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     nil,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	store.Close()

	// MustOpen should return error
	_, err = MustOpen(Config{
		DataDir:     dataDir,
		Setting:     nil,
		Logger:      logger,
		Interactive: false,
	})
	if err == nil {
		t.Fatal("MustOpen should return error for locked store")
	}
	if !strings.Contains(err.Error(), "keeper is locked") {
		t.Errorf("expected 'keeper is locked' error, got: %v", err)
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

// TestOpen_CreatesBucketAndReadsBack verifies the full round-trip with an
// explicit bucket creation and namespaced read.
func TestOpen_CreatesBucketAndReadsBack(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: expect.Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()

	store, err := Open(Config{
		DataDir:     dataDir,
		Setting:     cfg,
		Logger:      logger,
		Interactive: false,
	})
	if err != nil {
		t.Fatalf("Open failed: %v", err)
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

// TestResolvePassphrase verifies the passphrase resolution logic.
func TestResolvePassphrase(t *testing.T) {
	// Test with nil cfg
	if got := resolvePassphrase(nil); got != "" {
		t.Errorf("resolvePassphrase(nil) = %q, want empty", got)
	}

	// Test with cfg but empty passphrase
	cfg := &alaye.Keeper{
		Passphrase: expect.Value(""),
	}
	if got := resolvePassphrase(cfg); got != "" {
		t.Errorf("resolvePassphrase(empty) = %q, want empty", got)
	}

	// Test with cfg and passphrase
	cfg.Passphrase = expect.Value("my-passphrase")
	if got := resolvePassphrase(cfg); got != "my-passphrase" {
		t.Errorf("resolvePassphrase = %q, want 'my-passphrase'", got)
	}

	// Test env var works
	t.Setenv("AGBERO_PASSPHRASE", "env-pass")
	cfg.Passphrase = expect.Value("")
	if got := resolvePassphrase(cfg); got != "env-pass" {
		t.Errorf("resolvePassphrase with env = %q, want 'env-pass'", got)
	}

	// Test cfg takes precedence over env
	cfg.Passphrase = expect.Value("cfg-pass")
	if got := resolvePassphrase(cfg); got != "cfg-pass" {
		t.Errorf("resolvePassphrase with cfg = %q, want 'cfg-pass'", got)
	}
}

// containsError reports whether err contains the target substring.
func containsError(err error, target string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), target)
}
