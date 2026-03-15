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

## Configuration

```hcl
# hosts.d/example.hcl
domains = ["api.example.com"]

route "/api" {
  wasm {
    enabled = true
    module  = "/etc/agbero/plugins/auth.wasm"
    access  = ["headers", "config"]
    config = {
      "required_role" = "admin"
      "debug"         = "false"
      "api_keys"      = "key1,key2,key3"
    }
  }

  backend {
    server { address = "http://localhost:8080" }
  }
}
```

### WASM Block Fields

| Field    | Description                                  | Default  |
|----------|----------------------------------------------|----------|
| `enabled`  | Enable/disable this plugin                 | `false`  |
| `module`   | Path to the `.wasm` file                   | Required |
| `access`   | Permissions: `headers`, `config`           | `[]`     |
| `config`   | Key-value map passed to the plugin         | `{}`     |

### Access Permissions

| Permission | Description |
|------------|-------------|
| `headers`  | Read and write HTTP headers |
| `config`   | Read the `config` map from HCL |

---

## Host Functions API

Your plugin communicates with Agbero through a small set of imported host functions.

### `agbero_get_header` - Read Request Header

```rust
fn agbero_get_header(key_ptr: *const u8, key_len: usize,
                     val_ptr: *mut u8,  max_len: usize) -> usize;
```

**Parameters:**
- `key_ptr`, `key_len`: Header name (e.g. `"Authorization"`)
- `val_ptr`, `max_len`: Output buffer

**Returns:** Number of bytes written. `0` means the header was not present.

### `agbero_set_header` - Set Request Header

```rust
fn agbero_set_header(key_ptr: *const u8, key_len: usize,
                     val_ptr: *const u8, val_len: usize);
```

Sets a header on the outbound request (forwarded to the backend). Requires `headers` in `access`.

### `agbero_get_config` - Read Plugin Configuration

```rust
fn agbero_get_config(buf_ptr: *mut u8, buf_len: usize) -> usize;
```

**Parameters:**
- `buf_ptr`, `buf_len`: Output buffer for JSON configuration

**Returns:** Actual length of configuration JSON

**Behavior:** Copies JSON-serialized `config` map from HCL into buffer.

### `agbero_done` - Complete Request

```rust
fn agbero_done(status_code: u32)
```

**Parameters:**
- `status_code`: HTTP status code

**Behavior:**
- `0`: Continue to next middleware or backend
- `200-599`: Stop processing and respond with this status code

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
        // Debug output (visible in logs via response headers)
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

    // 3. Validate against API keys
    let token = auth_value.strip_prefix("Bearer ").unwrap_or(&auth_value);

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
# Rust 1.78+ (preferred)
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/agbero_auth.wasm ./auth.wasm

# Older Rust (still works)
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --release
cp target/wasm32-wasi/release/agbero_auth.wasm ./auth.wasm
```

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

//export agbero_get_header
func agbero_get_header(keyPtr, keyLen, valPtr, maxLen uint32) uint32

//export agbero_set_header
func agbero_set_header(keyPtr, keyLen, valPtr, valLen uint32)

//export agbero_get_config
func agbero_get_config(bufPtr, maxLen uint32) uint32

//export agbero_done
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
	cfLen := agbero_get_header(ptr(cfKey), len32(cfKey), ptr(cfBuf), 8)

	if cfLen > 0 {
		country := string(cfBuf[:cfLen])
		for _, blocked := range cfg.BlockCountries {
			if country == blocked {
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
		return uint32(uintptr(unsafe.Pointer(&[]byte(v)[0])))
	case []byte:
		return uint32(uintptr(unsafe.Pointer(&v[0])))
	}
	return 0
}

func len32(s string) uint32 { return uint32(len(s)) }

func main() {}
```

**Compile:**
```bash
tinygo build -o geo-block.wasm -target=wasi -no-debug main.go
```

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

    // Simple check for API key
    char auth_buf[256];
    unsigned int auth_len = agbero_get_header("Authorization", 13, auth_buf, 256);

    if (auth_len > 0 && strncmp(auth_buf, "Bearer secret", 13) == 0) {
        agbero_set_header("X-Auth", 6, "true", 4);
        agbero_done(0);
    } else {
        agbero_done(401);
    }
}
```

**Compile with WASI SDK:**
```bash
clang --target=wasm32-wasi -nostdlib -Wl,--no-entry \
      -Wl,--export=handle_request -o example.wasm example.c
```

---

## Testing Plugins Locally

1. **Create a test configuration:**

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
    }
  }

  web {
    root    = "./www"
    listing = true
  }
}
```

2. **Run Agbero in development mode:**
```bash
agbero run --dev
```

3. **Test with curl:**
```bash
# Should pass
curl -H "Authorization: Bearer secret" http://test.localhost/

# Should return 401
curl http://test.localhost/
```

---

## Performance Best Practices

1. **Minimize allocations** — pre-allocate buffers and reuse them
2. **Cache configuration** — parse JSON once and store in a static variable
3. **Request only needed permissions** — smaller `access` list means faster execution
4. **Keep plugins focused** — one plugin, one responsibility
5. **Use release builds** — always compile with optimizations enabled

---

## Debugging Plugins

### Enable Debug Mode

```hcl
wasm {
  config = {
    "debug" = "true"  # Plugin-specific debug flag
  }
}
```

### Logging from Plugins

Use response headers to surface debug values during development:

```rust
agbero_set_header(
    "X-WASM-Debug".as_ptr(), 12,
    "auth-check".as_ptr(), 10,
);
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Plugin not loading | Check file permissions and path |
| Memory access violation | Verify buffer sizes and bounds |
| Function not found | Ensure correct export name (`handle_request`) |
| Slow performance | Reduce allocations, check access list |

---

## Limitations

- **No filesystem access** — plugins cannot read or write files
- **No network access** — all I/O must go through host functions
- **Limited memory** — 1MB default per instance
- **No threads** — WASM is single-threaded

---

## Next Steps

- **Example Plugins** — check GitHub for ready-to-use plugins
- **Advanced Topics** — see [Advanced Guide](./advance.md) for clustering
- **API Reference** — see [API Guide](./api.md) for programmatic control