package tlss

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/security"
)

func TestDiskStorage_Plaintext(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewDiskStorage(woos.NewFolder(tmpDir), nil)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	domain := "example.com"
	certData := []byte("CERTIFICATE DATA")
	keyData := []byte("PRIVATE KEY DATA")

	if err := store.Save(domain, certData, keyData); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	safeName := "example.com"
	if _, err := os.Stat(filepath.Join(tmpDir, safeName+".key")); os.IsNotExist(err) {
		t.Error("Key file not created")
	}

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
	cipher, _ := security.NewCipher("secret-key-1234567890123456789012")

	store, err := NewDiskStorage(woos.NewFolder(tmpDir), cipher)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}

	domain := "secure.com"
	certData := []byte("CERTIFICATE DATA")
	keyData := []byte("SENSITIVE KEY DATA")

	if err := store.Save(domain, certData, keyData); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	safeName := "secure.com"
	diskKeyBytes, _ := os.ReadFile(filepath.Join(tmpDir, safeName+".key.enc"))

	if string(diskKeyBytes) == string(keyData) {
		t.Fatal("Key stored in plaintext on disk despite secret being set!")
	}

	_, loadedKey, err := store.Load(domain)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(loadedKey) != string(keyData) {
		t.Errorf("Decrypted key mismatch. Want %s, got %s", keyData, loadedKey)
	}
}

func TestDiskStorage_EncryptionFallback(t *testing.T) {
	tmpDir := t.TempDir()
	cipher, _ := security.NewCipher("new-secret-key-1234567890")

	domain := "legacy.com"
	safeName := "legacy.com"
	certData := []byte("CERT")
	keyData := []byte("-----BEGIN PRIVATE KEY-----\nDATA")

	os.WriteFile(filepath.Join(tmpDir, safeName+".crt"), certData, 0644)
	os.WriteFile(filepath.Join(tmpDir, safeName+".key"), keyData, 0600)

	store, err := NewDiskStorage(woos.NewFolder(tmpDir), cipher)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

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

	cipherA, _ := security.NewCipher("key-A-12345678901234567890")
	storeA, _ := NewDiskStorage(woos.NewFolder(tmpDir), cipherA)
	storeA.Save("test.com", []byte("C"), []byte("K"))

	cipherB, _ := security.NewCipher("key-B-99999999999999999999")
	storeB, _ := NewDiskStorage(woos.NewFolder(tmpDir), cipherB)
	_, _, err := storeB.Load("test.com")

	if err == nil {
		t.Fatal("Expected error loading with wrong key, got nil")
	}
}

func TestDiskStorage_ListAndDelete(t *testing.T) {
	tmpDir := t.TempDir()
	store, _ := NewDiskStorage(woos.NewFolder(tmpDir), nil)

	domains := []string{"a.com", "b.com", "*.c.com"}
	for _, d := range domains {
		store.Save(d, []byte("c"), []byte("k"))
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list))
	}

	if err := store.Delete("a.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	listAfter, _ := store.List()
	if len(listAfter) != 2 {
		t.Errorf("Expected 2 items after delete, got %d", len(listAfter))
	}

	_, _, err = store.Load("a.com")
	if !errors.Is(err, ErrCertNotFound) {
		t.Errorf("Expected ErrCertNotFound, got %v", err)
	}
}
