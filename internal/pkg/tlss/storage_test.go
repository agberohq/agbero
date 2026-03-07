package tlss

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
)

func TestDiskStorage_Plaintext(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewDiskStorage(woos.NewFolder(tmpDir), "")
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	domain := "example.com"
	certData := []byte("CERTIFICATE DATA")
	keyData := []byte("PRIVATE KEY DATA")

	// 1. Save
	if err := store.Save(domain, certData, keyData); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 2. Verify File Existence
	safeName := safeFileName(domain)
	if _, err := os.Stat(filepath.Join(tmpDir, safeName+".key")); os.IsNotExist(err) {
		t.Error("Key file not created")
	}

	// 3. Load
	loadedCert, loadedKey, err := store.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedCert) != string(certData) {
		t.Errorf("Cert mismatch. Want %s, got %s", certData, loadedCert)
	}
	if string(loadedKey) != string(keyData) {
		t.Errorf("Key mismatch. Want %s, got %s", keyData, loadedKey)
	}
}

func TestDiskStorage_Encrypted(t *testing.T) {
	tmpDir := t.TempDir()
	secret := "secret-key-1234567890123456789012" // 32+ chars

	store, err := NewDiskStorage(woos.NewFolder(tmpDir), secret)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	domain := "secure.com"
	certData := []byte("CERTIFICATE DATA")
	keyData := []byte("SENSITIVE KEY DATA")

	// 1. Save
	if err := store.Save(domain, certData, keyData); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 2. Verify Encryption on Disk
	safeName := safeFileName(domain)
	diskKeyBytes, _ := os.ReadFile(filepath.Join(tmpDir, safeName+".key"))

	if string(diskKeyBytes) == string(keyData) {
		t.Fatal("Key stored in plaintext on disk despite secret being set!")
	}

	// 3. Load (Should decrypt)
	_, loadedKey, err := store.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedKey) != string(keyData) {
		t.Errorf("Decrypted key mismatch. Want %s, got %s", keyData, loadedKey)
	}
}

func TestDiskStorage_EncryptionFallback(t *testing.T) {
	// Scenario: User upgrades Agbero and adds a secret key.
	// Existing keys on disk are plaintext. Loader should handle this.

	tmpDir := t.TempDir()
	secret := "new-secret-key-1234567890"

	// 1. Manually write plaintext key
	domain := "legacy.com"
	safeName := safeFileName(domain)
	certData := []byte("CERT")
	// Must start with hyphen for heuristic check in storage.go or be handleable
	keyData := []byte("-----BEGIN PRIVATE KEY-----\nDATA")

	os.WriteFile(filepath.Join(tmpDir, safeName+".crt"), certData, 0644)
	os.WriteFile(filepath.Join(tmpDir, safeName+".key"), keyData, 0600)

	// 2. Init store WITH secret
	store, err := NewDiskStorage(woos.NewFolder(tmpDir), secret)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// 3. Load should succeed via fallback
	_, loadedKey, err := store.Load(domain)
	if err != nil {
		t.Fatalf("Fallback load failed: %v", err)
	}

	if string(loadedKey) != string(keyData) {
		t.Error("Fallback loaded data mismatch")
	}
}

func TestDiskStorage_WrongKeyFail(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Save with Key A
	storeA, _ := NewDiskStorage(woos.NewFolder(tmpDir), "key-A-12345678901234567890")
	storeA.Save("test.com", []byte("C"), []byte("K"))

	// 2. Load with Key B
	storeB, _ := NewDiskStorage(woos.NewFolder(tmpDir), "key-B-99999999999999999999")
	_, _, err := storeB.Load("test.com")

	if err == nil {
		t.Fatal("Expected error loading with wrong key, got nil")
	}
	if err != security.ErrDecrypt {
		t.Logf("Got expected error type: %v", err)
	}
}

func TestDiskStorage_ListAndDelete(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewDiskStorage(woos.NewFolder(tmpDir), "")

	domains := []string{"a.com", "b.com", "*.c.com"}
	for _, d := range domains {
		store.Save(d, []byte("c"), []byte("k"))
	}

	// List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list))
	}

	// Delete
	if err := store.Delete("a.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify
	listAfter, _ := store.List()
	if len(listAfter) != 2 {
		t.Errorf("Expected 2 items after delete, got %d", len(listAfter))
	}

	_, _, err = store.Load("a.com")
	if !errors.Is(err, ErrCertNotFound) {
		t.Errorf("Expected ErrCertNotFound, got %v", err)
	}
}
