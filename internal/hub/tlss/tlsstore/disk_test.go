package tlsstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

func TestDiskStorage_SeparateDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		DataDir: dataDir,
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save domain cert (should go to certDir)
	certPEM := []byte("fake-cert")
	keyPEM := []byte("fake-key")

	if err := disk.Save(IssuerACME, "example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists in certDir

	if !certDir.FileExists(filepath.Join(IssuerACME, "example.com.crt")) {
		t.Error("Certificate not saved in certDir")
	}

	// Save CA cert (should go to dataDir)
	if err := disk.Save(IssuerCA, "ca", certPEM, keyPEM); err != nil {
		t.Fatalf("Save CA failed: %v", err)
	}

	// Verify CA file exists in dataDir
	if !dataDir.FileExists(IssuerCA, "ca.crt") {
		t.Error("CA certificate not saved in dataDir")
	}

	// Load domain cert
	loadedCert, loadedKey, err := disk.Load("example.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certPEM) {
		t.Errorf("Cert mismatch: got %s, want %s", loadedCert, certPEM)
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("Key mismatch: got %s, want %s", loadedKey, keyPEM)
	}
}

func TestDiskStorage_WithDataDirOnly(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))

	disk, err := NewDisk(DiskConfig{
		DataDir: dataDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save domain cert with only dataDir - should fallback to dataDir
	certPEM := []byte("test-cert")
	keyPEM := []byte("test-key")

	if err := disk.Save(IssuerCustom, "test.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Should be saved in dataDir since certDir not set
	if !dataDir.FileExists(IssuerCustom, "test.com.crt") {
		t.Error("Certificate not saved in dataDir")
	}

	// Load should work
	loadedCert, loadedKey, err := disk.Load("test.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certPEM) {
		t.Errorf("Cert mismatch")
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("Key mismatch")
	}
}

func TestDiskStorage_WithCertDirOnly(t *testing.T) {
	tmpDir := t.TempDir()
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save CA cert with only certDir - should fallback to certDir
	certPEM := []byte("ca-cert")
	keyPEM := []byte("ca-key")

	if err := disk.Save(IssuerCA, "ca", certPEM, keyPEM); err != nil {
		t.Fatalf("Save CA failed: %v", err)
	}

	// Should be saved in certDir since dataDir not set
	if !certDir.FileExists(IssuerCA, "ca.crt") {
		t.Error("CA certificate not saved")
	}
	// Load CA
	loadedCert, loadedKey, err := disk.Load("ca")
	if err != nil {
		t.Fatalf("Load CA failed: %v", err)
	}

	if string(loadedCert) != string(certPEM) {
		t.Errorf("CA cert mismatch")
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("CA key mismatch")
	}
}

func TestDiskStorage_Encrypted(t *testing.T) {
	tmpDir := t.TempDir()

	// Mock cipher for testing
	mockCipher := &mockCipher{}

	disk, err := NewDisk(DiskConfig{
		DataDir: expect.NewFolder(filepath.Join(tmpDir, "data")),
		CertDir: expect.NewFolder(filepath.Join(tmpDir, "certs")),
		Cipher:  mockCipher,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	certPEM := []byte("secret-cert")
	keyPEM := []byte("secret-key")

	if err := disk.Save(IssuerACME, "secure.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify key is encrypted
	keyPath := filepath.Join(tmpDir, "certs", IssuerACME, "secure.com.key.enc")
	encryptedKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted key: %v", err)
	}

	if string(encryptedKey) == string(keyPEM) {
		t.Error("Key stored in plaintext!")
	}

	// Load should decrypt automatically
	loadedCert, loadedKey, err := disk.Load("secure.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certPEM) {
		t.Errorf("Cert mismatch")
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("Key mismatch")
	}
}

func TestDiskStorage_Priority(t *testing.T) {
	tmpDir := t.TempDir()
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save same domain under different issuers
	customCert := []byte("custom-cert")
	customKey := []byte("custom-key")
	acmeCert := []byte("acme-cert")
	acmeKey := []byte("acme-key")

	if err := disk.Save(IssuerCustom, "priority.com", customCert, customKey); err != nil {
		t.Fatalf("Save custom failed: %v", err)
	}
	if err := disk.Save(IssuerACME, "priority.com", acmeCert, acmeKey); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}

	// Load should return custom (higher priority)
	loadedCert, loadedKey, err := disk.Load("priority.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(customCert) {
		t.Errorf("Expected custom cert, got %s", loadedCert)
	}
	if string(loadedKey) != string(customKey) {
		t.Errorf("Expected custom key, got %s", loadedKey)
	}
}

func TestDiskStorage_List(t *testing.T) {
	tmpDir := t.TempDir()
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	domains := []string{"a.com", "b.com", "*.c.com"}
	for _, d := range domains {
		if err := disk.Save(IssuerCustom, d, []byte("cert"), []byte("key")); err != nil {
			t.Fatalf("Save %s failed: %v", d, err)
		}
	}

	list, err := disk.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list))
	}

	// Check wildcard conversion
	found := false
	for _, d := range list {
		if d == "*.c.com" {
			found = true
		}
	}
	if !found {
		t.Error("Wildcard domain not properly converted")
	}
}

func TestDiskStorage_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		DataDir: dataDir,
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save certificates
	if err := disk.Save(IssuerACME, "delete.com", []byte("cert"), []byte("key")); err != nil {
		t.Fatalf("Save ACME failed: %v", err)
	}
	if err := disk.Save(IssuerCA, "ca", []byte("ca-cert"), []byte("ca-key")); err != nil {
		t.Fatalf("Save CA failed: %v", err)
	}

	// Delete domain
	if err := disk.Delete("delete.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify domain cert is gone
	_, _, err = disk.Load("delete.com")
	if err != ErrCertNotFound {
		t.Errorf("Expected ErrCertNotFound, got %v", err)
	}

	// CA cert should still exist
	_, _, err = disk.Load("ca")
	if err != nil {
		t.Errorf("CA cert should still exist: %v", err)
	}
}

func TestDiskStorage_LoadFallback_FromDataDirToCertDir(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		DataDir: dataDir,
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save only in dataDir (not in certDir)
	certPEM := []byte("data-only-cert")
	keyPEM := []byte("data-only-key")

	if err := disk.Save(IssuerCustom, "fallback.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load should find it in dataDir
	loadedCert, loadedKey, err := disk.Load("fallback.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certPEM) {
		t.Errorf("Cert mismatch")
	}
	if string(loadedKey) != string(keyPEM) {
		t.Errorf("Key mismatch")
	}
}

func TestDiskStorage_LoadPreference_CertDirOverDataDir(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := expect.NewFolder(filepath.Join(tmpDir, "data"))
	certDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))

	disk, err := NewDisk(DiskConfig{
		DataDir: dataDir,
		CertDir: certDir,
	})
	if err != nil {
		t.Fatalf("Failed to create disk storage: %v", err)
	}

	// Save same domain in both directories
	certDirCert := []byte("cert-dir-cert")
	certDirKey := []byte("cert-dir-key")
	dataDirCert := []byte("data-dir-cert")
	dataDirKey := []byte("data-dir-key")

	// Save in certDir
	if err := disk.Save(IssuerCustom, "preference.com", certDirCert, certDirKey); err != nil {
		t.Fatalf("Save to certDir failed: %v", err)
	}

	// Save in dataDir (by temporarily swapping config - but we can't easily do that)
	// Instead, we'll create a separate disk instance to write to dataDir
	diskDataOnly, err := NewDisk(DiskConfig{
		DataDir: dataDir,
	})
	if err != nil {
		t.Fatalf("Failed to create data-only disk: %v", err)
	}
	if err := diskDataOnly.Save(IssuerCustom, "preference.com", dataDirCert, dataDirKey); err != nil {
		t.Fatalf("Save to dataDir failed: %v", err)
	}

	// Load from main disk - should prefer certDir
	loadedCert, loadedKey, err := disk.Load("preference.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certDirCert) {
		t.Errorf("Expected cert from certDir, got %s", loadedCert)
	}
	if string(loadedKey) != string(certDirKey) {
		t.Errorf("Expected key from certDir, got %s", loadedKey)
	}
}

// Mock cipher for testing
type mockCipher struct{}

func (m *mockCipher) Encrypt(data []byte) ([]byte, error) {
	// Simple mock encryption - just reverse
	reversed := make([]byte, len(data))
	for i, b := range data {
		reversed[len(data)-1-i] = b
	}
	return reversed, nil
}

func (m *mockCipher) Decrypt(data []byte) ([]byte, error) {
	// Simple mock decryption - reverse back
	reversed := make([]byte, len(data))
	for i, b := range data {
		reversed[len(data)-1-i] = b
	}
	return reversed, nil
}
