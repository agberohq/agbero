package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHostManager_LoadAndGet(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two host files
	h1 := `server_names = ["a.com"]`
	h2 := `server_names = ["b.com"]`

	os.WriteFile(filepath.Join(tmpDir, "h1.hcl"), []byte(h1), 0644)
	os.WriteFile(filepath.Join(tmpDir, "h2.hcl"), []byte(h2), 0644)
	os.WriteFile(filepath.Join(tmpDir, "ignored.txt"), []byte("ignored"), 0644)

	hm := NewHost(tmpDir)

	// Test LoadAll
	hosts, err := hm.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}

	// Test Get (Case insensitive)
	cfg := hm.Get("A.com")
	if cfg == nil {
		t.Error("Get(A.com) returned nil")
	}

	cfg = hm.Get("unknown.com")
	if cfg != nil {
		t.Error("Get(unknown.com) should be nil")
	}
}
