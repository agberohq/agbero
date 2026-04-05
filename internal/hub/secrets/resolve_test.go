package secrets

import (
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/keeper"
)

func TestResolver_WireUnwire(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	// Unlock the store
	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create a bucket - this is required
	if err := store.CreateBucket("vault", "test-ns", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	testKey := "vault://test-ns/test-key"
	testValue := "test-value"

	// Set the value
	if err := store.Set(testKey, []byte(testValue)); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Verify it's there
	got, err := store.Get(testKey)
	if err != nil || string(got) != testValue {
		t.Fatalf("Store verification failed: got %s, want %s, err: %v", got, testValue, err)
	}

	resolver := NewResolver(store)

	// Test without Wire
	resolver.Unwire()
	val := expect.Value(testKey)
	resolved, err := resolver.Resolve(val)
	if err != expect.ErrStoreLocked {
		t.Errorf("Without Wire, expected ErrStoreLocked, got: %v", err)
	}

	// Wire the resolver
	resolver.Wire()
	defer resolver.Unwire()

	// Now resolution should work
	resolved, err = resolver.Resolve(val)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if resolved != testValue {
		t.Errorf("Resolved value mismatch: got %s, want %s", resolved, testValue)
	}
}

func TestResolver_ResolveNamespaced(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create buckets
	if err := store.CreateBucket("vault", "prod", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := store.CreateBucket("vault", "staging", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Set values in different namespaces
	if err := store.SetNamespacedFull("vault", "prod", "db-password", []byte("prod-secret")); err != nil {
		t.Fatalf("Set prod failed: %v", err)
	}
	if err := store.SetNamespacedFull("vault", "staging", "db-password", []byte("staging-secret")); err != nil {
		t.Fatalf("Set staging failed: %v", err)
	}

	resolver := NewResolver(store)

	// Test ResolveNamespaced
	resolved, err := resolver.ResolveNamespaced("vault", "prod", expect.Value("db-password"))
	if err != nil {
		t.Fatalf("ResolveNamespaced failed: %v", err)
	}
	if resolved != "prod-secret" {
		t.Errorf("Expected prod-secret, got %s", resolved)
	}

	// Test with different namespace
	resolved, err = resolver.ResolveNamespaced("vault", "staging", expect.Value("db-password"))
	if err != nil {
		t.Fatalf("ResolveNamespaced staging failed: %v", err)
	}
	if resolved != "staging-secret" {
		t.Errorf("Expected staging-secret, got %s", resolved)
	}
}

func TestResolver_MultipleSchemes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create buckets with different schemes
	if err := store.CreateBucket("vault", "system", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket vault failed: %v", err)
	}
	if err := store.CreateBucket("certs", "letsencrypt", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket certs failed: %v", err)
	}
	if err := store.CreateBucket("keeper", "tenant1", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket keeper failed: %v", err)
	}

	// Set values
	if err := store.Set("vault://system/api-key", []byte("vault-secret")); err != nil {
		t.Fatalf("Set vault failed: %v", err)
	}
	if err := store.Set("certs://letsencrypt/example.com", []byte("cert-data")); err != nil {
		t.Fatalf("Set certs failed: %v", err)
	}
	if err := store.Set("keeper://tenant1/db-password", []byte("tenant-secret")); err != nil {
		t.Fatalf("Set keeper failed: %v", err)
	}

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"vault scheme", "vault://system/api-key", "vault-secret"},
		{"certs scheme", "certs://letsencrypt/example.com", "cert-data"},
		{"keeper scheme", "keeper://tenant1/db-password", "tenant-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val := expect.Value(tt.key)
			resolved, err := resolver.Resolve(val)
			if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			if resolved != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, resolved)
			}
		})
	}
}

func TestResolver_WithDifferentPrefixes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create bucket
	if err := store.CreateBucket("vault", "test", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	testValue := "test-secret-value"
	if err := store.Set("vault://test/mykey", []byte(testValue)); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	// Test different prefix formats that Value supports
	prefixes := []string{
		"ss://vault://test/mykey",   // ss:// prefix
		"ss.vault://test/mykey",     // ss. prefix
		"keeper.vault://test/mykey", // keeper. prefix
	}

	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			val := expect.Value(prefix)
			resolved, err := resolver.Resolve(val)
			if err != nil {
				t.Fatalf("Resolve with prefix %s failed: %v", prefix, err)
			}
			if resolved != testValue {
				t.Errorf("Expected %s, got %s", testValue, resolved)
			}
		})
	}
}

func TestResolver_Unwire(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create bucket and set value
	if err := store.CreateBucket("vault", "test", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	testValue := "secret-value"
	if err := store.Set("vault://test/mykey", []byte(testValue)); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	resolver := NewResolver(store)

	// Wire and verify it works
	resolver.Wire()
	val := expect.Value("vault://test/mykey")
	resolved, err := resolver.Resolve(val)
	if err != nil {
		t.Fatalf("Resolve after wire failed: %v", err)
	}
	if resolved != testValue {
		t.Errorf("Expected %s, got %s", testValue, resolved)
	}

	// Unwire and verify it fails
	resolver.Unwire()
	_, err = resolver.Resolve(val)
	if err != expect.ErrStoreLocked {
		t.Errorf("After unwire, expected ErrStoreLocked, got: %v", err)
	}
}

func TestResolver_NonExistentKey(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create bucket
	if err := store.CreateBucket("vault", "test", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	// Try to resolve a non-existent key
	val := expect.Value("vault://test/nonexistent")
	resolved, err := resolver.Resolve(val)

	// Should return the original key and no error
	if err != nil && err != keeper.ErrKeyNotFound {
		t.Errorf("Unexpected error: %v", err)
	}
	if resolved == "" {
		t.Error("Expected non-empty result for missing key")
	}
}

func TestResolver_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := keeper.New(keeper.Config{DBPath: dbPath})
	if err != nil {
		t.Fatalf("Failed to create keeper: %v", err)
	}
	defer store.Close()

	if err := store.Unlock([]byte("test-passphrase-32-bytes-long!!")); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	// Empty key should resolve to empty string
	val := expect.Value("")
	resolved, err := resolver.Resolve(val)
	if err != nil {
		t.Errorf("Resolve empty key failed: %v", err)
	}
	if resolved != "" {
		t.Errorf("Expected empty string, got %s", resolved)
	}
}
