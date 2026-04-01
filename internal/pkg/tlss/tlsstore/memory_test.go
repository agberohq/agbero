// tlsstore/memory_test.go
package tlsstore

import (
	"testing"
)

func TestMemoryStorage_Basic(t *testing.T) {
	store := NewMemory()

	// Save certificates under different issuers
	certPEM := []byte("test-cert")
	keyPEM := []byte("test-key")

	if err := store.Save(IssuerACME, "example.com", certPEM, keyPEM); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load should work
	loadedCert, loadedKey, err := store.Load("example.com")
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

func TestMemoryStorage_Priority(t *testing.T) {
	store := NewMemory()

	// Save same domain under different issuers
	store.Save(IssuerCustom, "priority.com", []byte("custom-cert"), []byte("custom-key"))
	store.Save(IssuerACME, "priority.com", []byte("acme-cert"), []byte("acme-key"))
	store.Save(IssuerLocal, "priority.com", []byte("local-cert"), []byte("local-key"))

	// Load should return custom (highest priority)
	cert, key, err := store.Load("priority.com")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if string(cert) != "custom-cert" {
		t.Errorf("Expected custom-cert, got %s", cert)
	}
	if string(key) != "custom-key" {
		t.Errorf("Expected custom-key, got %s", key)
	}
}

func TestMemoryStorage_List(t *testing.T) {
	store := NewMemory()

	domains := []string{"a.com", "b.com", "*.c.com"}
	for _, d := range domains {
		store.Save(IssuerCustom, d, []byte("cert"), []byte("key"))
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 3 {
		t.Errorf("Expected 3 items, got %d", len(list))
	}
}

func TestMemoryStorage_Delete(t *testing.T) {
	store := NewMemory()

	store.Save(IssuerACME, "delete.com", []byte("cert"), []byte("key"))
	store.Save(IssuerCA, "ca", []byte("ca-cert"), []byte("ca-key"))

	// Delete domain
	if err := store.Delete("delete.com"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify domain is gone
	_, _, err := store.Load("delete.com")
	if err != ErrCertNotFound {
		t.Errorf("Expected ErrCertNotFound, got %v", err)
	}

	// CA should still exist
	_, _, err = store.Load("ca")
	if err != nil {
		t.Errorf("CA should still exist: %v", err)
	}
}
