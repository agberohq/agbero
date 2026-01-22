package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostManager_LoadAndGet(t *testing.T) {
	tmpDir := t.TempDir()

	h1 := `domains = ["a.com"]`
	h2 := `domains = ["b.com", "B2.com"]`

	if err := os.WriteFile(filepath.Join(tmpDir, "h1.hcl"), []byte(h1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "h2.hcl"), []byte(h2), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "ignored.txt"), []byte("ignored"), 0644); err != nil {
		t.Fatal(err)
	}

	hm := NewHost(tmpDir)

	hosts, err := hm.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(hosts))
	}

	if cfg := hm.Get("A.com"); cfg == nil {
		t.Error("Get(A.com) returned nil")
	}
	if cfg := hm.Get("b2.COM"); cfg == nil {
		t.Error("Get(b2.COM) returned nil")
	}
	if cfg := hm.Get("unknown.com"); cfg != nil {
		t.Error("Get(unknown.com) should be nil")
	}
}

// waitUntil repeatedly checks cond until it returns true or we hit deadline.
func waitUntil(t *testing.T, deadline time.Time, cond func() bool) {
	t.Helper()
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met before deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// drainChanged drains any pending change signals to reduce flakiness from coalescing.
func drainChanged(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
			continue
		default:
			return
		}
	}
}

func TestHostManager_Watch_CreateUpdateRemove(t *testing.T) {
	tmpDir := t.TempDir()
	hm := NewHost(tmpDir)

	h1Path := filepath.Join(tmpDir, "x.hcl")
	if err := os.WriteFile(h1Path, []byte(`domains=["x.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := hm.Watch(); err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	defer hm.Close()

	// Ensure initial load is visible
	waitUntil(t, time.Now().Add(2*time.Second), func() bool {
		return hm.Get("x.com") != nil
	})

	// Clear any initial signals
	drainChanged(hm.Changed())

	// UPDATE
	if err := os.WriteFile(h1Path, []byte(`domains=["x.com","y.com"]`), 0644); err != nil {
		t.Fatal(err)
	}

	// We might get multiple signals; wait for at least one.
	select {
	case <-hm.Changed():
	case <-time.After(2 * time.Second):
		t.Fatalf("expected change signal on update")
	}

	// But signal != state; poll until y.com is visible.
	waitUntil(t, time.Now().Add(2*time.Second), func() bool {
		return hm.Get("y.com") != nil
	})

	// Clear signals before remove to avoid waking on an older one.
	drainChanged(hm.Changed())

	// REMOVE
	if err := os.Remove(h1Path); err != nil {
		t.Fatal(err)
	}

	// On macOS you may get rename/chmod/write/remove combos; just wait for a signal.
	select {
	case <-hm.Changed():
	case <-time.After(2 * time.Second):
		t.Fatalf("expected change signal on remove")
	}

	// Now poll until removal is actually applied.
	waitUntil(t, time.Now().Add(2*time.Second), func() bool {
		return hm.Get("x.com") == nil && hm.Get("y.com") == nil
	})
}
