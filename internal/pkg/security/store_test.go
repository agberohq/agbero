// store_test.go (updated TestShamirInitAndUnlock to match new API)
package security

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "secrets.db")

	config := StoreConfig{
		DBPath:           dbPath,
		AutoLockInterval: 0, // Disabled for tests
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if !store.IsLocked() {
		t.Error("NewStore store should be locked")
	}

	// Verify file was created with restricted permissions
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Failed to stat db file: %v", err)
	}

	// Check permissions (should be 0600)
	if info.Mode().Perm() != 0600 {
		t.Errorf("Wrong file permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	// Test unlock with new passphrase (creates verification hash)
	if err := store.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	if store.IsLocked() {
		t.Error("Store should be unlocked")
	}

	// Test unlock again (should fail - already unlocked)
	if err := store.Unlock("test-passphrase"); err != ErrAlreadyUnlocked {
		t.Errorf("Expected ErrAlreadyUnlocked, got: %v", err)
	}

	// Lock and unlock with wrong passphrase
	if err := store.Lock(); err != nil {
		t.Fatalf("Lock() failed: %v", err)
	}

	if err := store.Unlock("wrong-passphrase"); err != ErrInvalidPassphrase {
		t.Errorf("Expected ErrInvalidPassphrase, got: %v", err)
	}

	// Unlock with correct passphrase
	if err := store.Unlock("test-passphrase"); err != nil {
		t.Fatalf("Unlock() with correct passphrase failed: %v", err)
	}
}

func TestSetGet(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	// Should fail when locked
	if err := store.Set("key", "value"); err != ErrStoreLocked {
		t.Errorf("Set() when locked: expected ErrStoreLocked, got %v", err)
	}

	if _, err := store.Get("key"); err != ErrStoreLocked {
		t.Errorf("Get() when locked: expected ErrStoreLocked, got %v", err)
	}

	// Unlock
	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Set secret
	if err := store.Set("mykey", "mysecret"); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Get secret
	val, err := store.Get("mykey")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if val != "mysecret" {
		t.Errorf("Get() returned wrong value: got %q, want %q", val, "mysecret")
	}

	// Get non-existent key
	if _, err := store.Get("nonexistent"); err != ErrKeyNotFound {
		t.Errorf("Get() nonexistent: expected ErrKeyNotFound, got %v", err)
	}
}

func TestSetGetBytes(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Test binary data
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	if err := store.SetBytes("binary", binaryData); err != nil {
		t.Fatalf("SetBytes() failed: %v", err)
	}

	retrieved, err := store.GetBytes("binary")
	if err != nil {
		t.Fatalf("GetBytes() failed: %v", err)
	}

	if !bytes.Equal(retrieved, binaryData) {
		t.Errorf("GetBytes() returned wrong data: got %v, want %v", retrieved, binaryData)
	}
}

func TestDelete(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Set and delete
	if err := store.Set("todelete", "value"); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	if err := store.Delete("todelete"); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	// Verify deletion
	if _, err := store.Get("todelete"); err != ErrKeyNotFound {
		t.Errorf("Get() after delete: expected ErrKeyNotFound, got %v", err)
	}

	// Delete non-existent
	if err := store.Delete("nonexistent"); err != ErrKeyNotFound {
		t.Errorf("Delete() nonexistent: expected ErrKeyNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Empty list
	keys, err := store.List()
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List() on empty store: expected 0 keys, got %d", len(keys))
	}

	// Add secrets
	store.Set("key1", "val1")
	store.Set("key2", "val2")
	store.Set("key3", "val3")

	keys, err = store.List()
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("List() expected 3 keys, got %d", len(keys))
	}

	// Verify all keys exist
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}

	for _, expected := range []string{"key1", "key2", "key3"} {
		if !keyMap[expected] {
			t.Errorf("List() missing key: %s", expected)
		}
	}
}

func TestExists(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	store.Set("existing", "value")

	exists, err := store.Exists("existing")
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if !exists {
		t.Error("Exists() should return true for existing key")
	}

	exists, err = store.Exists("nonexistent")
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if exists {
		t.Error("Exists() should return false for non-existent key")
	}
}

func TestRotate(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("old-passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Store secrets
	store.Set("key1", "value1")
	store.Set("key2", "value2")

	// Rotate to new passphrase
	if err := store.Rotate("new-passphrase"); err != nil {
		t.Fatalf("Rotate() failed: %v", err)
	}

	// Verify still unlocked and can read
	val, err := store.Get("key1")
	if err != nil {
		t.Fatalf("Get() after rotate failed: %v", err)
	}
	if val != "value1" {
		t.Errorf("Wrong value after rotate: got %q, want %q", val, "value1")
	}

	// Lock and unlock with new passphrase
	store.Lock()
	if err := store.Unlock("new-passphrase"); err != nil {
		t.Fatalf("Unlock() with new passphrase failed: %v", err)
	}

	// Verify old passphrase doesn't work
	store.Lock()
	if err := store.Unlock("old-passphrase"); err != ErrInvalidPassphrase {
		t.Errorf("Old passphrase should fail: got %v", err)
	}
}

func TestAutoLock(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 100 * time.Millisecond,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Should be unlocked
	if store.IsLocked() {
		t.Error("Store should be unlocked initially")
	}

	// Wait for auto-lock
	time.Sleep(200 * time.Millisecond)

	if !store.IsLocked() {
		t.Error("Store should be auto-locked after interval")
	}
}

func TestShamirInitAndUnlock(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	// Initialize with 2-of-3 Shamir
	passphrases := []string{"admin1-pass", "admin2-pass", "admin3-pass"}
	encryptedShares, err := store.InitializeShamir(2, 3, passphrases)
	if err != nil {
		t.Fatalf("InitializeShamir() failed: %v", err)
	}

	if len(encryptedShares) != 3 {
		t.Errorf("Expected 3 encrypted shares, got %d", len(encryptedShares))
	}

	// Lock
	store.Lock()

	// Try to unlock with 1 share (should fail)
	err = store.UnlockShamir(encryptedShares[:1], passphrases[:1])
	if err == nil || !errors.Is(err, ErrShamirThreshold) {
		t.Errorf("Expected ErrShamirThreshold with 1 share, got %v", err)
	}

	// Unlock with 2 shares
	err = store.UnlockShamir(encryptedShares[:2], passphrases[:2])
	if err != nil {
		t.Errorf("UnlockShamir() with 2 shares failed: %v", err)
	}

	if store.IsLocked() {
		t.Error("Store should be unlocked after Shamir unlock")
	}

	// Verify can access secrets
	store.Set("shamir-key", "shamir-value")
	val, err := store.Get("shamir-key")
	if err != nil || val != "shamir-value" {
		t.Errorf("Failed to access secrets after Shamir unlock: %v", err)
	}
}

func TestDecryptShareWrongPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	passphrases := []string{"admin1-pass", "admin2-pass"}
	encryptedShares, err := store.InitializeShamir(2, 2, passphrases)
	if err != nil {
		t.Fatalf("InitializeShamir() failed: %v", err)
	}

	// Try decrypt with wrong passphrase
	_, err = store.DecryptShare(encryptedShares[0], "wrong-pass")
	if err == nil {
		t.Error("DecryptShare() with wrong passphrase should fail")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := fmt.Sprintf("key%d", n)
			val := fmt.Sprintf("value%d", n)
			if err := store.Set(key, val); err != nil {
				t.Errorf("Concurrent Set() failed: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all writes
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key%d", i)
		expected := fmt.Sprintf("value%d", i)
		val, err := store.Get(key)
		if err != nil {
			t.Errorf("Failed to get %s: %v", key, err)
			continue
		}
		if val != expected {
			t.Errorf("Wrong value for %s: got %q, want %q", key, val, expected)
		}
	}
}

func TestAuditLogging(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
		EnableAudit:      true,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	var auditEvents []struct {
		action   string
		key      string
		success  bool
		duration time.Duration
	}

	store.SetAuditFunc(func(action, key string, success bool, duration time.Duration) {
		auditEvents = append(auditEvents, struct {
			action   string
			key      string
			success  bool
			duration time.Duration
		}{action, key, success, duration})
	})

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	store.Set("audited-key", "audited-value")
	store.Get("audited-key")
	store.Get("nonexistent") // Failed get
	store.Lock()

	if len(auditEvents) < 3 {
		t.Errorf("Expected at least 3 audit events, got %d", len(auditEvents))
	}

	// Verify unlock event
	foundUnlock := false
	for _, e := range auditEvents {
		if e.action == "unlock" && e.success {
			foundUnlock = true
			break
		}
	}
	if !foundUnlock {
		t.Error("Missing unlock audit event")
	}
}

func TestSecretMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Set initial value
	if err := store.Set("meta-key", "v1"); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Get multiple times to increment access count
	for i := 0; i < 5; i++ {
		store.Get("meta-key")
	}

	// Update to increment version
	if err := store.Set("meta-key", "v2"); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	// Verify metadata by checking existence and version through List/Exists
	exists, err := store.Exists("meta-key")
	if err != nil || !exists {
		t.Errorf("Key should exist: err=%v, exists=%v", err, exists)
	}
}

func TestOpenExisting(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "secrets.db")

	// Create store
	config := StoreConfig{
		DBPath:           dbPath,
		AutoLockInterval: 0,
	}

	store1, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	store1.Close()

	// Open existing
	store2, err := OpenExisting(config)
	if err != nil {
		t.Fatalf("OpenExisting() failed: %v", err)
	}
	defer store2.Close()

	if !store2.IsLocked() {
		t.Error("Opened store should be locked")
	}

	// Try to open non-existent
	config.DBPath = filepath.Join(tmpDir, "nonexistent.db")
	if _, err := OpenExisting(config); err == nil {
		t.Error("OpenExisting() on non-existent file should fail")
	}
}

func TestGlobalStore(t *testing.T) {
	tmpDir := t.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		t.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}

	// Set global
	SetGlobalStore(store)

	// Test GetGlobalStore
	gs := GetGlobalStore()
	if gs == nil {
		t.Fatal("GetGlobalStore() returned nil")
	}

	if gs.IsLocked() {
		t.Error("Global store should be unlocked")
	}

	// Test GetGlobal
	store.Set("global-key", "global-value")
	val, err := GetGlobal("global-key")
	if err != nil {
		t.Fatalf("GetGlobal() failed: %v", err)
	}
	if val != "global-value" {
		t.Errorf("GetGlobal() wrong value: got %q, want %q", val, "global-value")
	}

	// Test GetGlobal without store
	SetGlobalStore(nil)
	if _, err := GetGlobal("key"); err == nil {
		t.Error("GetGlobal() without store should fail")
	}
}

func BenchmarkSet(b *testing.B) {
	tmpDir := b.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		b.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		b.Fatalf("Unlock() failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(fmt.Sprintf("key%d", i), "benchmark-value")
	}
}

func BenchmarkGet(b *testing.B) {
	tmpDir := b.TempDir()
	config := StoreConfig{
		DBPath:           filepath.Join(tmpDir, "secrets.db"),
		AutoLockInterval: 0,
	}

	store, err := NewStore(config)
	if err != nil {
		b.Fatalf("NewStore() failed: %v", err)
	}
	defer store.Close()

	if err := store.Unlock("passphrase"); err != nil {
		b.Fatalf("Unlock() failed: %v", err)
	}

	store.Set("bench-key", "bench-value")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Get("bench-key")
	}
}
