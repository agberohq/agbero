# Agbero Plugin Guide: WebAssembly Middleware

Agbero supports a powerful plugin system powered by **WebAssembly (WASM)** via the `wazero` runtime. This allows you to write custom middleware in any language that compiles to WASM (Go, Rust, C++, Zig) and execute it safely inside the proxy with near-native performance.

## Why use WASM Plugins?

1.  **Custom Logic:** Implement specific business rules (e.g., inspecting specific headers or JWT tokens) without maintaining a custom fork of Agbero.
2.  **Memory Safety:** Plugins execute in an isolated sandbox. Memory leaks or panics inside the plugin will never crash the core Agbero proxy.
3.  **Hot Reloading:** Modify your `.wasm` binary and execute an `agbero reload` to seamlessly swap out the logic with zero dropped connections.
4.  **Language Agnostic:** Write middleware in Rust or Go depending on your team's expertise.

## 1. How It Works

When a request matches a route containing a `wasm` block:

1.  Agbero checks its sync pool for a warm WASM instance.
2.  Agbero invokes the exported `handle_request()` function within your module.
3.  Your module executes, calling **Host Functions** (Agbero's API) to read request data or mutate response headers.
4.  Your module calls `agbero_done(status)`. A status of `0` tells Agbero to continue the proxy chain. Any status `> 0` tells Agbero to abort the chain and respond immediately with that HTTP status code.

## 2. Configuration

Enable the plugin directly within your routing definitions.

```hcl
# hosts.d/api.hcl
route "/secure/api" {
  wasm {
    enabled = true
    module  = "./plugins/auth.wasm"
    
    # Security: Explicitly grant permissions. 
    # Plugins attempting to access ungranted capabilities will receive empty data.
    access =["headers", "config"]
    
    # Configuration passed to the plugin (retrieved via agbero_get_config)
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

Agbero enforces strict memory isolation.

| Permission | Description |
| :--- | :--- |
| `headers` | Read (`agbero_get_header`) and Write (`agbero_set_header`) HTTP headers. |
| `config` | Read the JSON-serialized `config` map provided in the HCL file. |

## 3. Host Function API Reference

These functions are mounted in the `env` namespace within the WASM runtime.

### `agbero_get_header(key_ptr, key_len, buf_ptr, buf_len) -> val_len`
*   **Input**: Memory pointer and length indicating the header key to look up. Memory pointer and length representing your allocated output buffer.
*   **Output**: Returns the **actual length** of the header value.
*   **Behavior**: Copies the header value into your buffer. Truncates silently if your provided buffer is too small.

### `agbero_set_header(key_ptr, key_len, val_ptr, val_len)`
*   **Input**: Pointers and lengths for the Key and Value strings.
*   **Behavior**: Sets a header. If the plugin allows the request, this header is attached to the request sent to the backend. If the plugin blocks the request, this header is attached to the immediate HTTP response sent to the client.

### `agbero_get_config(buf_ptr, buf_len) -> json_len`
*   **Input**: Pointer and length representing your allocated output buffer.
*   **Output**: Length of the JSON string.
*   **Behavior**: Copies the JSON-serialized `config` map from your HCL file into the buffer.

### `agbero_done(status_code)`
*   **Input**: HTTP Status Code (uint32).
*   **Behavior**:
    *   `0`: **Success/Continue**. Agbero proceeds to the next middleware or routes to the backend.
    *   `200-599`: **Stop/Abort**. Agbero halts processing and responds to the client with the provided HTTP status code.

## 4. Writing a Plugin (Go / TinyGo)

We strongly recommend **TinyGo** as it produces highly optimized, small WASM binaries suitable for high-throughput edge proxies.

### Create `main.go`

```go
package main

import (
	"unsafe"
)

// --- Host Function API ---

//export agbero_get_header
func agbero_get_header(keyPtr, keyLen, valPtr, maxLen uint32) uint32

//export agbero_set_header
func agbero_set_header(keyPtr, keyLen, valPtr, valLen uint32)

//export agbero_get_config
func agbero_get_config(bufPtr, maxLen uint32) uint32

//export agbero_done
func agbero_done(status uint32)

// --- Core Logic ---

//export handle_request
func handle_request() {
	key := "Authorization"
	buf := make([]byte, 256)
	
	valLen := agbero_get_header(
		ptr(key), len32(key),
		ptr(buf), 256,
	)
	
	// Block if header is missing or empty
	if valLen == 0 {
		agbero_done(401)
		return
	}

	token := string(buf[:valLen])

	// Validate token
	if token == "Bearer secret-admin-key" {
		// Set a header for the backend to consume
		setKey := "X-Role"
		setVal := "Admin"
		agbero_set_header(
			ptr(setKey), len32(setKey),
			ptr(setVal), len32(setVal),
		)
		
		agbero_done(0) // Proceed to backend
	} else {
		agbero_done(403) // Forbidden
	}
}

func main() {}

// --- Memory Helpers ---

func ptr(s interface{}) uint32 {
	switch v := s.(type) {
	case string:
		return uint32(uintptr(unsafe.Pointer(&[]byte(v)[0])))
	case []byte:
		return uint32(uintptr(unsafe.Pointer(&v[0])))
	}
	return 0
}

func len32(s string) uint32 { 
    return uint32(len(s)) 
}
```

### Compile the Plugin

```bash
tinygo build -o auth.wasm -target=wasi -no-debug main.go
```

## 5. Writing a Plugin (Rust)

Rust offers excellent memory control and produces highly efficient WASM artifacts.

### Create `lib.rs`

```rust
#[link(wasm_import_module = "env")]
extern "C" {
    fn agbero_get_header(k: *const u8, kl: usize, v: *mut u8, ml: usize) -> usize;
    fn agbero_done(status: u32);
}

#[no_mangle]
pub extern "C" fn handle_request() {
    let key = "User-Agent";
    let mut buf =[0u8; 128];
    
    unsafe {
        let len = agbero_get_header(key.as_ptr(), key.len(), buf.as_mut_ptr(), 128);
        
        // Block simple curl bots
        if len >= 4 && &buf[0..4] == b"curl" {
             agbero_done(403);
             return;
        }
        
        agbero_done(0);
    }
}
```

### Compile the Plugin

```bash
cargo build --target wasm32-wasi --release
```

## 6. Performance Best Practices

*   **Avoid Allocations:** Pre-allocate buffers and reuse them within your WASM code. Heap allocations inside WASM can create minor latency spikes.
*   **Cache Configuration:** If you need to parse JSON from `agbero_get_config`, do it lazily the first time the module executes and cache the result. The `wazero` instance persists in memory between requests.
*   **Target Scope:** Only request the capabilities (`access` list) you strictly require. This allows Agbero to skip memory context preparations for unused features.