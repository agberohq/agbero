package expect

import (
	"testing"

	"path/filepath"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/ll"
)

func TestResolver_WireUnwire(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create the bucket before writing
	if err := store.CreateBucket("vault", "test-ns", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	testKey := "vault://test-ns/test-key"
	testValue := "test-value"
	if err := store.Set(testKey, []byte(testValue)); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	resolver := NewResolver(store)

	// Test without Wire - should return original key because storeLookupFn is nil
	resolver.Unwire() // Ensure no lookup function is set
	val := Value(testKey)
	resolved, err := resolver.Resolve(val)
	if err != ErrStoreLocked {
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
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

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
	resolved, err := resolver.ResolveNamespaced("vault", "prod", Value("db-password"))
	if err != nil {
		t.Fatalf("ResolveNamespaced failed: %v", err)
	}
	if resolved != "prod-secret" {
		t.Errorf("Expected prod-secret, got %s", resolved)
	}

	// Test with different namespace
	resolved, err = resolver.ResolveNamespaced("vault", "staging", Value("db-password"))
	if err != nil {
		t.Fatalf("ResolveNamespaced staging failed: %v", err)
	}
	if resolved != "staging-secret" {
		t.Errorf("Expected staging-secret, got %s", resolved)
	}
}

func TestResolver_MultipleSchemes(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

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
			val := Value(tt.key)
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
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

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

	// Test different prefix formats that alaye.Value supports
	prefixes := []string{
		"ss://vault://test/mykey",   // ss:// prefix
		"ss.vault://test/mykey",     // ss. prefix
		"keeper.vault://test/mykey", // keeper. prefix
	}

	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			val := Value(prefix)
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
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

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
	val := Value("vault://test/mykey")
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
	if err != ErrStoreLocked {
		t.Errorf("After unwire, expected ErrStoreLocked, got: %v", err)
	}
}

func TestResolver_NonExistentKey(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create bucket
	if err := store.CreateBucket("vault", "test", keeper.LevelPasswordOnly, "test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	// Try to resolve a non-existent key
	val := Value("vault://test/nonexistent")
	resolved, err := resolver.Resolve(val)

	// Should return the original key and no error (or maybe a not found error)
	if err != nil && err != keeper.ErrKeyNotFound {
		t.Errorf("Unexpected error: %v", err)
	}
	if resolved == "" {
		t.Error("Expected non-empty result for missing key")
	}
}

func TestResolver_EmptyKey(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	cfg := &alaye.Keeper{
		Enabled:    alaye.Active,
		Passphrase: Value("test-passphrase-32-bytes-long!!"),
	}
	logger := ll.New("test").Disable()
	store, err := security.OpenStore(dataDir, cfg, logger)
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	resolver := NewResolver(store)
	resolver.Wire()
	defer resolver.Unwire()

	// Empty key should resolve to empty string
	val := Value("")
	resolved, err := resolver.Resolve(val)
	if err != nil {
		t.Errorf("Resolve empty key failed: %v", err)
	}
	if resolved != "" {
		t.Errorf("Expected empty string, got %s", resolved)
	}
}
