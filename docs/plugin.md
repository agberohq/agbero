# Agbero WebAssembly Plugin Guide

Agbero supports WebAssembly (WASM) middleware plugins that run inside the request pipeline. Plugins can inspect and modify request headers, read route configuration, and short-circuit requests — all without modifying Agbero's source code.

## How It Works

```
Client Request
      │
      ▼
┌─────────────┐
│   Agbero    │
│  Pipeline   │
│             │
│ ┌─────────┐ │
│ │  WASM   │ │  ← Your plugin runs here
│ │ Plugin  │ │
│ └────┬────┘ │
│      │      │
│  continue   │
│   or stop   │
└─────┬───────┘
      │
      ▼
    Backend
```

Each request passes through your plugin before reaching the backend. The plugin can:
- Read any request header
- Set new headers (forwarded to the backend)
- Stop the request with any HTTP status code
- Read its own configuration from the HCL file
- Access request body, method, and URI (with proper permissions)

---

## Configuration

```hcl
# hosts.d/example.hcl
domains = ["api.example.com"]

route "/api" {
  wasm {
    enabled = true
    module  = "/etc/agbero/plugins/auth.wasm"
    max_body_size = 1048576  # 1MB maximum body to inspect (optional)
    
    # Explicitly grant capabilities
    access = ["headers", "config", "body", "method", "uri"]
    
    # Configuration passed to plugin (as JSON)
    config = {
      "required_role" = "admin"
      "debug"         = "false"
      "api_keys"      = ["key1", "key2", "key3"]
    }
  }

  backend {
    server { address = "http://localhost:8080" }
  }
}
```

### WASM Block Fields

| Field | Description | Required |
|-------|-------------|----------|
| `enabled` | Enable/disable this plugin | Yes |
| `module` | Path to the `.wasm` file | Yes |
| `max_body_size` | Maximum body size to read (bytes) | No |
| `access` | Permissions: `headers`, `config`, `body`, `method`, `uri` | Yes |
| `config` | Key-value map passed to the plugin | No |

### Access Permissions

| Permission | Description |
|------------|-------------|
| `headers` | Read and write HTTP headers |
| `config` | Read the `config` map from HCL |
| `body` | Access request body |
| `method` | Access HTTP method |
| `uri` | Access request URI |

---

## Host Functions API

Your plugin communicates with Agbero through a set of imported host functions. All functions are imported from the `env` module.

### `agbero_get_header` - Read Request Header

Reads a header value from the incoming request.

**Signature:**
```rust
fn agbero_get_header(key_ptr: *const u8, key_len: usize,
                     val_ptr: *mut u8, max_len: usize) -> usize;
```

**Parameters:**
- `key_ptr`, `key_len`: Header name (e.g. `"Authorization"`)
- `val_ptr`, `max_len`: Output buffer and its size

**Returns:** Number of bytes written to `val_ptr`. Returns `0` if header not found.

**Access Required:** `headers`

---

### `agbero_set_header` - Set Request Header

Sets a header on the outbound request (forwarded to the backend).

**Signature:**
```rust
fn agbero_set_header(key_ptr: *const u8, key_len: usize,
                     val_ptr: *const u8, val_len: usize);
```

**Parameters:**
- `key_ptr`, `key_len`: Header name
- `val_ptr`, `val_len`: Header value

**Access Required:** `headers`

---

### `agbero_get_config` - Read Plugin Configuration

Reads the plugin's configuration as a JSON string. The config comes from the `config` map in your HCL.

**Signature:**
```rust
fn agbero_get_config(buf_ptr: *mut u8, buf_len: usize) -> usize;
```

**Parameters:**
- `buf_ptr`, `buf_len`: Output buffer for configuration JSON

**Returns:** Actual length of configuration JSON. If the buffer is too small, returns the required size.

**Access Required:** `config`

**Example Config JSON:**
```json
{
  "required_role": "admin",
  "debug": false,
  "api_keys": ["key1", "key2", "key3"]
}
```

---

### `agbero_done` - Complete Request

Signals that the plugin has finished processing and indicates what should happen next.

**Signature:**
```rust
fn agbero_done(status_code: u32)
```

**Parameters:**
- `status_code`: HTTP status code or 0 to continue

**Behavior:**
- `0`: Continue to next middleware or backend
- `200-599`: Stop processing and respond with this status code

**Access Required:** None (always available)

---

## Writing Plugins

### Option 1: Rust (Recommended)

Rust offers excellent memory safety and produces highly optimized WASM binaries.

**Cargo.toml:**
```toml
[package]
name = "agbero-auth"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

**src/lib.rs:**
```rust
use serde::Deserialize;
use std::slice;

#[link(wasm_import_module = "env")]
extern "C" {
    fn agbero_get_header(k: *const u8, kl: usize, v: *mut u8, ml: usize) -> usize;
    fn agbero_set_header(k: *const u8, kl: usize, v: *const u8, vl: usize);
    fn agbero_get_config(buf: *mut u8, len: usize) -> usize;
    fn agbero_done(status: u32);
}

#[derive(Deserialize, Debug)]
struct Config {
    required_role: String,
    debug: bool,
    api_keys: Vec<String>,
}

#[no_mangle]
pub unsafe extern "C" fn handle_request() {
    // 1. Get configuration
    let mut config_buf = [0u8; 4096];
    let config_len = agbero_get_config(config_buf.as_mut_ptr(), 4096);

    if config_len == 0 {
        agbero_done(500);
        return;
    }

    let config_json = String::from_utf8_lossy(&config_buf[..config_len]);
    let config: Config = match serde_json::from_str(&config_json) {
        Ok(c) => c,
        Err(_) => {
            agbero_done(500);
            return;
        }
    };

    if config.debug {
        // Debug output could be added as response headers
        let debug_header = "X-WASM-Debug";
        let debug_value = "auth-check";
        agbero_set_header(
            debug_header.as_ptr(),
            debug_header.len(),
            debug_value.as_ptr(),
            debug_value.len(),
        );
    }

    // 2. Get Authorization header
    let auth_key = "Authorization";
    let mut auth_buf = [0u8; 512];
    let auth_len = agbero_get_header(
        auth_key.as_ptr(),
        auth_key.len(),
        auth_buf.as_mut_ptr(),
        512,
    );

    if auth_len == 0 {
        agbero_done(401);
        return;
    }

    let auth_value = String::from_utf8_lossy(&auth_buf[..auth_len]);
    let token = auth_value.strip_prefix("Bearer ").unwrap_or(&auth_value);

    // 3. Validate against API keys
    if config.api_keys.iter().any(|key| key == token) {
        // Set user header for backend
        let user_header = "X-Authenticated-User";
        let user_value = "api-user";
        agbero_set_header(
            user_header.as_ptr(),
            user_header.len(),
            user_value.as_ptr(),
            user_value.len(),
        );

        agbero_done(0); // Continue to backend
    } else {
        agbero_done(403); // Forbidden
    }
}
```

**Compile:**
```bash
# For Rust 1.78+ (recommended)
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/agbero_auth.wasm ./auth.wasm

# For older Rust versions
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --release
cp target/wasm32-wasi/release/agbero_auth.wasm ./auth.wasm
```

---

### Option 2: TinyGo

Go developers can use TinyGo to compile to WASM.

**main.go:**
```go
package main

import (
	"encoding/json"
	"unsafe"
)

type Config struct {
	BlockCountries []string `json:"block_countries"`
	Debug          bool     `json:"debug_mode"`
}

//go:wasmimport env agbero_get_header
func agbero_get_header(keyPtr, keyLen, valPtr, maxLen uint32) uint32

//go:wasmimport env agbero_set_header
func agbero_set_header(keyPtr, keyLen, valPtr, valLen uint32)

//go:wasmimport env agbero_get_config
func agbero_get_config(bufPtr, maxLen uint32) uint32

//go:wasmimport env agbero_done
func agbero_done(status uint32)

//export handle_request
func handle_request() {
	// Get configuration
	configJSON := getConfig()

	var cfg Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		agbero_done(500)
		return
	}

	// Get Cloudflare country header
	cfKey := "CF-IPCountry"
	cfBuf := make([]byte, 8)
	cfLen := agbero_get_header(ptr(cfKey), uint32(len(cfKey)), ptr(cfBuf), 8)

	if cfLen > 0 {
		country := string(cfBuf[:cfLen])
		for _, blocked := range cfg.BlockCountries {
			if country == blocked {
				if cfg.Debug {
					debugHeader := "X-Blocked-Country"
					agbero_set_header(ptr(debugHeader), uint32(len(debugHeader)), 
                                     ptr(country), uint32(len(country)))
				}
				agbero_done(403)
				return
			}
		}
	}

	agbero_done(0) // Continue
}

func getConfig() string {
	buf := make([]byte, 4096)
	n := agbero_get_config(ptr(buf), 4096)
	return string(buf[:n])
}

func ptr(s interface{}) uint32 {
	switch v := s.(type) {
	case string:
		return uint32(uintptr(unsafe.Pointer(unsafe.StringData(v))))
	case []byte:
		return uint32(uintptr(unsafe.Pointer(&v[0])))
	}
	return 0
}

func main() {}
```

**Compile:**
```bash
tinygo build -o geo-block.wasm -target=wasi -no-debug main.go
```

---

### Option 3: C/C++

**example.c:**
```c
#include <string.h>

extern unsigned int agbero_get_header(const char* key, unsigned int key_len,
                                      char* buf, unsigned int buf_len);
extern void agbero_set_header(const char* key, unsigned int key_len,
                              const char* val, unsigned int val_len);
extern unsigned int agbero_get_config(char* buf, unsigned int buf_len);
extern void agbero_done(unsigned int status);

void handle_request() {
    char config_buf[4096];
    unsigned int config_len = agbero_get_config(config_buf, 4096);
    
    // Simple API key check
    char auth_buf[256];
    unsigned int auth_len = agbero_get_header("Authorization", 13, auth_buf, 256);

    if (auth_len > 5 && strncmp(auth_buf, "Bearer ", 7) == 0) {
        char* token = auth_buf + 7;
        if (strcmp(token, "secret-key-123") == 0) {
            agbero_set_header("X-Auth", 6, "true", 4);
            agbero_done(0);
            return;
        }
    }
    
    agbero_done(401);
}
```

**Compile with WASI SDK:**
```bash
# Install WASI SDK first: https://github.com/WebAssembly/wasi-sdk
clang --target=wasm32-wasi -nostdlib -Wl,--no-entry \
      -Wl,--export=handle_request \
      -o example.wasm example.c
```

---

## Plugin Lifecycle

1. **Load**: Plugin is loaded when the route is first accessed
2. **Instantiate**: A new instance is created (or reused from pool)
3. **Handle**: `handle_request()` is called for each request
4. **Done**: Plugin calls `agbero_done()` to continue or respond
5. **Reuse**: Instance returns to pool for future requests

### Instance Pooling

Agbero maintains a pool of WASM instances for performance. Multiple requests may reuse the same instance sequentially (not concurrently).

---

## Testing Plugins Locally

### 1. Create a test configuration

```hcl
# hosts.d/test.hcl
domains = ["test.localhost"]

route "/" {
  wasm {
    enabled = true
    module  = "./auth.wasm"
    access  = ["headers", "config"]
    config = {
      "debug" = "true"
      "api_keys" = ["test-key-123"]
    }
  }

  web {
    root    = "./www"
    listing = true
  }
}
```

### 2. Run Agbero in development mode

```bash
agbero run --dev
```

### 3. Test with curl

```bash
# Should pass
curl -H "Authorization: Bearer test-key-123" http://test.localhost/

# Should return 401
curl http://test.localhost/

# Should return 403 (wrong key)
curl -H "Authorization: Bearer wrong-key" http://test.localhost/
```

---

## Performance Best Practices

1. **Minimize allocations** — Pre-allocate buffers and reuse them
2. **Cache configuration** — Parse JSON once and store in static variable
3. **Request only needed permissions** — Smaller `access` list means faster execution
4. **Keep plugins focused** — One plugin, one responsibility
5. **Use release builds** — Always compile with optimizations enabled
6. **Set appropriate `max_body_size`** — Only read as much body as needed
7. **Return early** — Call `agbero_done()` as soon as decision is made

---

## Debugging Plugins

### Enable Debug Mode in Config

```hcl
wasm {
  config = {
    "debug" = "true"  # Plugin-specific debug flag
  }
}
```

### Use Response Headers for Debugging

```rust
if config.debug {
    agbero_set_header(
        "X-WASM-Debug".as_ptr(), 12,
        "auth-check".as_ptr(), 10,
    );
}
```

### Check Logs

Agbero logs WASM errors at the `error` level:

```
ERROR wasm: failed to instantiate module: module="auth.wasm" err="unknown import"
ERROR wasm: execution failed: err="memory access out of bounds"
```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Plugin not loading | Check file permissions and path |
| `unknown import` | Function name mismatch or missing export |
| Memory access violation | Verify buffer sizes and bounds |
| Function not found | Ensure correct export name (`handle_request`) |
| Slow performance | Reduce allocations, check access list |
| Config not available | Add `config` to `access` list |
| Headers not working | Add `headers` to `access` list |

### Memory Limits

- **Default max body size**: 5MB (configurable via `max_body_size`)
- **Instance memory**: 1MB default (managed by wazero)
- **Stack size**: Sufficient for typical plugin operations

---

## Security Considerations

1. **Capability-based security**: Plugins only have access to explicitly granted permissions
2. **No filesystem access**: Plugins cannot read or write files
3. **No network access**: All I/O must go through host functions
4. **Limited memory**: Prevents DoS via memory exhaustion
5. **Instance isolation**: Each plugin runs in its own sandbox

### Permission Principles

- Grant only the minimum permissions needed
- `headers` for header inspection/modification
- `config` for reading configuration
- `body` only when body inspection is absolutely necessary
- `method` and `uri` rarely needed separately (usually comes with headers)

---

## Advanced: Custom Host Functions

While not currently supported, the WASM host module (`internal/middleware/wasm/host.go`) can be extended with additional host functions. Each function must:

1. Be added to the host module builder
2. Include proper memory safety checks
3. Respect capability-based permissions

Example host function pattern:

```go
builder.NewFunctionBuilder().
    WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
        // 1. Extract parameters from stack
        // 2. Validate inputs and bounds
        // 3. Check permissions
        // 4. Perform operation
        // 5. Write results back to stack
    }), paramTypes, returnTypes).
    Export("agbero_custom_function")
```

---

## Example Plugins

### Authentication Plugin
Validates JWT tokens and extracts claims to headers.

### Rate Limiting Plugin
Implements custom rate limiting logic.

### Request Transformer
Modifies requests before they reach the backend.

### Response Filter
Filters or modifies responses from the backend.

### Geo-blocking Plugin
Blocks requests from specific countries (using Cloudflare headers).

---

## Next Steps

- **Example Repository**: Check GitHub for ready-to-use plugins
- **Advanced Features**: See [Advanced Guide](./advance.md) for clustering and distributed state
- **API Reference**: See [API Guide](./api.md) for dynamic route management
- **Contributing**: See [Contributor Guide](./contributor.md) for extending the WASM host
