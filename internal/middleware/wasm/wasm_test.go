package wasm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/ll"
)

// TestWasmMiddleware_EndToEnd compiles a real WASM module using TinyGo
// and tests the entire request flow (Host -> Guest -> Host).
func TestWasmMiddleware_EndToEnd(t *testing.T) {
	// Check if tinygo is installed
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("tinygo not found, skipping wasm integration test")
	}

	// Create a temporary Go file that will become our WASM module
	tmpDir := t.TempDir()
	goSrc := filepath.Join(tmpDir, "main.go")
	wasmOut := filepath.Join(tmpDir, "test.wasm")

	// This WASM code checks for Header "X-Secret".
	// If value == "open-sesame", it sets "X-Active" = "Allowed" and continues (200).
	// Otherwise, it calls agbero_done(401).
	code := `
package main

import (
	"unsafe"
)

//export agbero_get_header
func agbero_get_header(keyPtr, keyLen, valPtr, maxLen uint32) uint32

//export agbero_set_header
func agbero_set_header(keyPtr, keyLen, valPtr, valLen uint32)

//export agbero_done
func agbero_done(status uint32)

//export handle_request
func handle_request() {
	key := "X-Secret"
	valBuf := make([]byte, 64)
	
	// Read Header
	l := agbero_get_header(
		uint32(uintptr(unsafe.Pointer(&[]byte(key)[0]))),
		uint32(len(key)),
		uint32(uintptr(unsafe.Pointer(&valBuf[0]))),
		64,
	)
	secret := string(valBuf[:l])

	// Logic
	if secret == "open-sesame" {
		// Set Response Header
		outKey := "X-Active"
		outVal := "Allowed"
		agbero_set_header(
			uint32(uintptr(unsafe.Pointer(&[]byte(outKey)[0]))),
			uint32(len(outKey)),
			uint32(uintptr(unsafe.Pointer(&[]byte(outVal)[0]))),
			uint32(len(outVal)),
		)
		// Allow (0 = OK)
		agbero_done(0)
	} else {
		// Block (401)
		agbero_done(401)
	}
}

func main() {}
`
	if err := os.WriteFile(goSrc, []byte(code), woos.FilePerm); err != nil {
		t.Fatal(err)
	}

	// Compile to WASM: tinygo build -o test.wasm -target=wasi main.go
	cmd := exec.Command("tinygo", "build", "-o", wasmOut, "-target=wasi", "-no-debug", goSrc)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile wasm: %v\n%s", err, out)
	}

	// Initialize Resource
	logger := ll.New("test").Disable()
	cfg := &alaye.Wasm{
		Module: wasmOut,
		Access: []string{"headers"}, // Required permissions
	}

	mgr, err := NewManager(context.Background(), logger, cfg)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer mgr.Close(context.Background())

	// Build Handler Chain
	// The "Next" handler simply writes "Active"
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("Active"))
	})

	h := mgr.Handler(finalHandler)

	// Test Case A: Active (Correct Secret)
	t.Run("Authorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Secret", "open-sesame")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Expected 200, got %d", w.Code)
		}

		if w.Header().Get("X-Active") != "Allowed" {
			t.Errorf("Expected header X-Active=Allowed, got %q", w.Header().Get("X-Active"))
		}
		if w.Body.String() != "Active" {
			t.Errorf("Expected body 'Active', got %q", w.Body.String())
		}
	})

	// Test Case B: Failure (Wrong Secret)
	t.Run("Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Secret", "wrong-password")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != 401 {
			t.Errorf("Expected 401, got %d", w.Code)
		}
		// Should NOT call final handler, so body should be empty (or whatever http.Error writes)
		if w.Body.String() == "Active" {
			t.Error("Middleware should have blocked the request, but it reached final handler")
		}
	})
}

func TestWasmMiddleware_Permissions(t *testing.T) {
	// This test ensures that if Access=[]string{}, the WASM module cannot read headers
	// even if it tries.
	if _, err := exec.LookPath("tinygo"); err != nil {
		t.Skip("tinygo not found")
	}

	tmpDir := t.TempDir()
	goSrc := filepath.Join(tmpDir, "perm.go")
	wasmOut := filepath.Join(tmpDir, "perm.wasm")

	// This code tries to read "X-Secret". If it gets ANY data, it returns 200.
	// If it gets length 0 (permission denied behavior), it returns 403.
	code := `
package main
import "unsafe"
//export agbero_get_header
func agbero_get_header(k, kl, v, ml uint32) uint32
//export agbero_done
func agbero_done(s uint32)

//export handle_request
func handle_request() {
	key := "X-Secret"
	buf := make([]byte, 10)
	l := agbero_get_header(
		uint32(uintptr(unsafe.Pointer(&[]byte(key)[0]))),
		uint32(len(key)),
		uint32(uintptr(unsafe.Pointer(&buf[0]))),
		10,
	)
	if l > 0 {
		agbero_done(200) // Accessed successfully
	} else {
		agbero_done(403) // Access denied (empty return)
	}
}
func main() {}
`
	os.WriteFile(goSrc, []byte(code), woos.FilePerm)
	exec.Command("tinygo", "build", "-o", wasmOut, "-target=wasi", "-no-debug", goSrc).Run()

	// Config with NO permissions
	cfg := &alaye.Wasm{
		Module: wasmOut,
		Access: []string{}, // Empty!
	}

	mgr, _ := NewManager(context.Background(), ll.New("test").Disable(), cfg)
	defer mgr.Close(context.Background())

	h := mgr.Handler(http.NotFoundHandler())

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Secret", "data")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Errorf("Expected 403 (Permission Denied), got %d. The WASM module was able to read headers despite empty Access list.", w.Code)
	}
}
