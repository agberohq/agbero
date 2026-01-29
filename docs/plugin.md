# Agbero Plugin Guide: WebAssembly Middleware

Agbero supports a powerful plugin system powered by **WebAssembly (WASM)**. This allows you to write custom middleware in any language that compiles to WASM (Go, Rust, TinyGo, Zig, C++, etc.) and run it safely inside the proxy with near-native performance.

## Why use WASM Plugins?

1.  **Custom Logic:** Implement specific business rules (e.g., "Block requests from User-ID 123 if header X is missing") without modifying Agbero's source code.
2.  **Safety:** Plugins run in a sandboxed memory space. A crash in your plugin **will not** crash the server.
3.  **Hot Reload:** You can update the `.wasm` file and reload Agbero without dropping connections.
4.  **Language Choice:** Write middleware in Rust or TypeScript instead of Go if your team prefers it.

---

## 1. How It Works

When a request matches a route with a configured `wasm_middleware`:

1.  Agbero instantiates a lightweight WASM Virtual Machine (using `wazero`).
2.  Agbero calls the exported function `handle_request()` in your module.
3.  Your module calls **Host Functions** (Agbero's API) to read headers, check config, or modify the response.
4.  Your module tells Agbero to either **Continue** to the backend or **Stop** (e.g., return 401).

---

## 2. Writing a Plugin (Go / TinyGo)

We recommend **TinyGo** because it produces very small WASM binaries suitable for edge proxies.

### Step 1: Create `main.go`

```go
package main

import (
	"unsafe"
)

// --- Host Function Definitions (The API) ---

// Get a header value. Returns length of value written to valPtr.
//export agbero_get_header
func agbero_get_header(keyPtr, keyLen, valPtr, maxLen uint32) uint32

// Set a response header.
//export agbero_set_header
func agbero_set_header(keyPtr, keyLen, valPtr, valLen uint32)

// Get configuration JSON passed from HCL.
//export agbero_get_config
func agbero_get_config(bufPtr, maxLen uint32) uint32

// Signal completion. status=0 means "Allow/Continue", status > 0 means "Block with Status".
//export agbero_done
func agbero_done(status uint32)

// --- Your Logic ---

//export handle_request
func handle_request() {
	// 1. Read "Authorization" Header
	key := "Authorization"
	buf := make([]byte, 256)
	
	valLen := agbero_get_header(
		ptr(key), len32(key),
		ptr(buf), 256,
	)
	
	// If header is missing (len 0) or empty
	if valLen == 0 {
		agbero_done(401) // Unauthorized
		return
	}

	token := string(buf[:valLen])

	// 2. Simple Validation Logic
	if token == "secret-admin-key" {
		// Set a header for the backend to see
		setKey := "X-Role"
		setVal := "Admin"
		agbero_set_header(
			ptr(setKey), len32(setKey),
			ptr(setVal), len32(setVal),
		)
		
		// 3. Allow Request
		agbero_done(0)
	} else {
		// Block
		agbero_done(403)
	}
}

func main() {}

// --- Helpers ---
func ptr(s interface{}) uint32 {
	switch v := s.(type) {
	case string:
		return uint32(uintptr(unsafe.Pointer(&[]byte(v)[0])))
	case []byte:
		return uint32(uintptr(unsafe.Pointer(&v[0])))
	}
	return 0
}

func len32(s string) uint32 { return uint32(len(s)) }
```

### Step 2: Compile

```bash
tinygo build -o auth.wasm -target=wasi -no-debug main.go
```

---

## 3. Writing a Plugin (Rust)

Rust has excellent WASM support.

```rust
// lib.rs
#[link(wasm_import_module = "env")]
extern "C" {
    fn agbero_get_header(k: *const u8, kl: usize, v: *mut u8, ml: usize) -> usize;
    fn agbero_done(status: u32);
}

#[no_mangle]
pub extern "C" fn handle_request() {
    let key = "User-Agent";
    let mut buf = [0u8; 128];
    
    unsafe {
        let len = agbero_get_header(key.as_ptr(), key.len(), buf.as_mut_ptr(), 128);
        
        // If User-Agent starts with "curl"
        if len >= 4 && &buf[0..4] == b"curl" {
             agbero_done(403); // Block bots
             return;
        }
        
        agbero_done(0); // Allow
    }
}
```

Compile with: `cargo build --target wasm32-wasi --release`

---

## 4. Configuration

Enable the plugin in your `agbero.hcl` file.

```hcl
route "/secure/api" {
  # Load the WASM module
  wasm {
    module = "./plugins/auth.wasm"
    
    # Security: Explicitly grant permissions. 
    # If a plugin tries to access a capability not listed here, it fails silently or returns empty data.
    access = ["headers", "config"]
    
    # Configuration passed to the plugin (read via agbero_get_config)
    config = {
      "required_role" = "super-admin"
      "debug_mode"    = "true"
    }
  }

  backend {
    server { address = "http://localhost:8080" }
  }
}
```

### Access Control (`access` list)

Agbero enforces strict permissions. A plugin cannot read headers unless you allow it.

| Permission | Description |
| :--- | :--- |
| `headers` | Read (`agbero_get_header`) and Write (`agbero_set_header`) headers. |
| `config` | Read the user-provided config JSON (`agbero_get_config`). |
| `body` | (Future) Read/Write request body. *Warning: Performance cost.* |
| `uri` | (Future) Read/Write request path and query. |

---

## 5. Host Function API Reference

These functions are available in the `env` namespace.

### `agbero_get_header(key_ptr, key_len, buf_ptr, buf_len) -> val_len`
*   **Input**: Pointer/Len to header name string. Pointer/Len to your output buffer.
*   **Output**: Returns the **actual length** of the value.
*   **Behavior**: Copies the header value into your buffer. Truncates if buffer is too small.

### `agbero_set_header(key_ptr, key_len, val_ptr, val_len)`
*   **Input**: Key and Value strings.
*   **Behavior**: Sets a header on the **Response** (if blocking) or the **Request** (if continuing to backend).

### `agbero_get_config(buf_ptr, buf_len) -> json_len`
*   **Input**: Output buffer.
*   **Output**: Length of the JSON string.
*   **Behavior**: Copies the serialized `config` map from HCL into your buffer. You typically parse this JSON inside the plugin.

### `agbero_done(status_code)`
*   **Input**: HTTP Status Code (uint32).
*   **Behavior**:
    *   `0`: **Success**. Agbero proceeds to the next middleware or backend.
    *   `200-599`: **Stop**. Agbero stops processing and returns this status code to the client immediately.

---

## 6. Performance Tips

1.  **Use TinyGo**: Standard Go binaries are large (2MB+). TinyGo binaries are tiny (10KB-100KB) and instantiate much faster.
2.  **Avoid Large Allocations**: Reuse buffers in your WASM code if possible.
3.  **Config Parsing**: Parse your JSON config once (using a lazy static or init function) if your language supports it, or parse it only when needed. Note that `wazero` instances are transient per request, so persistent state requires specific techniques (like `wasi` file handles, future feature). For now, assume stateless execution.
4.  **Limit Access**: Only grant `access = ["headers"]` if you don't need body access. This allows Agbero to optimize data copying.