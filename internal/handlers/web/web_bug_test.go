package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestCrossTenantDataLeak_DynamicGzip(t *testing.T) {
	// Create two separate "tenant" roots
	rootA := newTestRoot(t)
	rootB := newTestRoot(t)

	// Both tenants have a file with the exact same path but different content.
	// We make them large enough (>1024 bytes) to trigger dynamic gzip.
	contentA := strings.Repeat("A", 1500)
	contentB := strings.Repeat("B", 1500)

	writeFile(t, rootA, "app.js", contentA)
	writeFile(t, rootB, "app.js", contentB)

	// Create web handlers pointing to the respective roots
	handlerA := newHandler(t, rootA)
	handlerB := newHandler(t, rootB)

	// Tenant A gets requested, which forces "app.js" into the global dynamicGzCache
	rrA := do(t, handlerA, http.MethodGet, "/app.js", acceptGzip())
	if rrA.Code != http.StatusOK {
		t.Fatalf("Tenant A request failed: %d", rrA.Code)
	}
	if gotA := decompressGzip(t, rrA); gotA != contentA {
		t.Fatalf("Tenant A got wrong content: expected %d 'A's", len(contentA))
	}

	// Tenant B gets requested for the SAME path "/app.js"
	// Before the fix, this would serve Tenant A's cached gzip data!
	rrB := do(t, handlerB, http.MethodGet, "/app.js", acceptGzip())
	if rrB.Code != http.StatusOK {
		t.Fatalf("Tenant B request failed: %d", rrB.Code)
	}

	// Verify Tenant B gets its own data
	gotB := decompressGzip(t, rrB)
	if gotB == contentA {
		t.Fatal("CRITICAL: Cross-tenant data leak! Tenant B was served Tenant A's cached file.")
	}
	if gotB != contentB {
		t.Fatalf("Tenant B got wrong content. Expected %d 'B's", len(contentB))
	}
}
