# Agbero

**Agbero** is a high-performance, lightweight, and production-ready reverse proxy and web server written in Go. It is designed for simplicity, featuring automatic HTTPS (via Let's Encrypt), hot-reloading configuration, and robust rate limiting.

Agbero uses **HCL (HashiCorp Configuration Language)** for its configuration, making it significantly more readable and maintainable than JSON or YAML alternatives.

## 🚀 Features

*   **Automatic HTTPS**: Zero-config TLS certificates via Let's Encrypt (Production & Staging).
*   **Hot Reloading**: Add, remove, or modify host configurations without restarting the server.
*   **Simple Configuration**: clean and human-readable HCL syntax.
*   **Load Balancing**: Supports `RoundRobin`, `LeastConn`, and `Random` strategies.
*   **Static Site Hosting**: Serve static files efficiently with safe root confinement.
*   **Rate Limiting**: robust, distributed-ready rate limiting (Global & Per-route policies).
*   **Middleware**: Trusted Proxy (Real IP) resolution, Security Headers, and Request Logging.
*   **Cross-Platform Service**: Native daemon support for **Linux (systemd)**, **Windows (SCM)**, and **macOS (Launchd)**.

---

## 📦 Installation

### Option 1: Build from Source
Requirements: Go 1.21+

```bash
git clone https://git.imaxinacion.net/aibox/agbero.git
cd agbero
go build -o agbero cmd/agbero/*.go
```

### Option 2: Automatic Setup (Recommended)
Agbero includes a built-in installer that detects your OS, creates the necessary directory structures, and writes default configuration files.

```bash
# Linux / macOS (requires sudo)
sudo ./agbero install

# Windows (Run PowerShell as Administrator)
.\agbero.exe install
```

This command will:
1.  Create configuration directories (e.g., `/etc/agbero` or `C:\ProgramData\agbero`).
2.  Generate a default `config.hcl`.
3.  Register Agbero as a system service.

---

## 🛠 Usage & Commands

Agbero uses a subcommand structure.

| Command | Description |
| :--- | :--- |
| `install` | Installs default configs and registers the system service. |
| `uninstall`| Removes the system service. |
| `start` | Starts the background system service. |
| `stop` | Stops the background system service. |
| `run` | Runs the proxy in the foreground (interactive mode). |
| `validate` | Checks the configuration file for syntax errors. |
| `hosts` | Lists all currently loaded host configurations. |

### Global Flags
*   `-c, --config`: Path to the global config file (Default: `/etc/agbero/config.hcl` or OS equivalent).
*   `-d, --dev`: Enable development mode (Debug logging, Let's Encrypt Staging).

---

## ⚙️ Configuration

Agbero uses a split configuration model:
1.  **Global Config** (`config.hcl`): Server-wide settings (ports, email, timeouts).
2.  **Host Configs** (`hosts.d/*.hcl`): Per-domain settings (routes, backends, SSL).

### 1. Global Configuration (`config.hcl`)

```hcl
# Listen addresses
bind = ":80 :443"

# Path to hosts directory. 
# If relative (e.g., "./hosts.d"), it resolves relative to this config file.
hosts_dir = "./hosts.d"

# Email used for Let's Encrypt registration
le_email = "admin@example.com"

# Trusted proxies (CIDR) for Real-IP resolution
trusted_proxies = ["127.0.0.1/32", "10.0.0.0/8"]

# Connection Timeouts
timeouts {
  read        = "10s"
  write       = "30s"
  idle        = "120s"
  read_header = "5s"
}

# Rate Limiting Definitions
rate_limits {
  ttl         = "30m"    # How long to keep IP data in memory
  max_entries = 100000   # Max IPs to track
  
  # Prefixes that trigger the 'auth' limit policy
  auth_prefixes = ["/login", "/otp", "/admin"]

  # Default limit for all traffic
  global {
    requests = 120
    window   = "1s"
    burst    = 240
  }

  # Stricter limit for auth routes
  auth {
    requests = 10
    window   = "1m"
  }
}
```

### 2. Host Configuration (`hosts.d/mysite.hcl`)

Drop `.hcl` files into the `hosts_dir`. Agbero watches this folder and updates automatically.

**Example: Reverse Proxy with Load Balancing**

```hcl
domains = ["api.example.com", "www.api.example.com"]

# Optional: TLS Settings
tls {
  mode = "letsencrypt" # Options: "letsencrypt", "local", "none"
  # If local:
  # local {
  #   cert_file = "/path/to/cert.pem"
  #   key_file  = "/path/to/key.pem"
  # }
}

# Optional: Request Limits
limits {
  max_body_size = 5242880 # 5MB
}

# Route Definition
route "/api/v1/*" {
  # Load Balancing Strategy: "roundrobin" (default), "random", "least_conn"
  lb_strategy = "least_conn"
  
  # Upstream Backends
  backends = [
    "http://10.0.0.1:8080",
    "http://10.0.0.2:8080"
  ]
  
  # Strip prefix before forwarding
  strip_prefixes = ["/api/v1"]
}

# Catch-all route
route "*" {
  backends = ["http://localhost:3000"]
}
```

**Example: Static Website**

```hcl
domains = ["example.com"]

web {
  root  = "/var/www/html"
  index = "index.html"
}
```

---

## 🛡️ TLS / SSL Handling

Agbero handles TLS automatically.

1.  **Let's Encrypt (Default)**:
    *   Set `tls { mode = "letsencrypt" }` in the host config.
    *   Ensure port 80 and 443 are open and mapped to the server.
    *   Certificates are stored in the `tls_storage_dir` (Default: `/var/lib/agbero/certmagic`).

2.  **Local Certificates**:
    *   Useful for internal networks or custom CAs.
    ```hcl
    tls {
      mode = "local"
      local {
        cert_file = "./certs/fullchain.pem"
        key_file  = "./certs/privkey.pem"
      }
    }
    ```

3.  **Development Mode**:
    Running `./agbero run --dev` switches Let's Encrypt to the **Staging** API. This prevents hitting rate limits while testing.

---

## 🚦 Service Management

Agbero uses the native service manager of the operating system.

**Windows**:
```powershell
# Install and Start
.\agbero.exe install
.\agbero.exe start

# Logs are sent to the Windows Event Viewer (Application Log)
```

**Linux (Systemd)**:
```bash
# Quick Run
sudo ./agbero run

# Install and Start
sudo ./agbero install
sudo ./agbero start

# Check Status
systemctl status agbero

# View Logs
journalctl -u agbero -f
```

---

## 📂 Directory Structure

Recommended structure for production:

```text
/etc/agbero/
├── config.hcl           # Main configuration
└── hosts.d/             # Host configurations
    ├── website-a.hcl
    └── api-service.hcl

/var/lib/agbero/         # Persistent data
└── certmagic/           # Let's Encrypt certificates
```

---

## 🤝 Contributing

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes.
4.  Push to the branch.
5.  Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.