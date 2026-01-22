package config

// ---- GLOBAL CONFIG -------------------------------------------

type GlobalConfig struct {
	Bind           string         `hcl:"bind"`
	HostsDir       string         `hcl:"hosts_dir"`
	LEEmail        string         `hcl:"le_email,optional"`
	LogLevel       string         `hcl:"log_level,optional"`
	Development    bool           `hcl:"development,optional"`
	TrustedProxies []string       `hcl:"trusted_proxies,optional"`
	Timeouts       *TimeoutConfig `hcl:"timeouts,block"`
}

type TimeoutConfig struct {
	Read       string `hcl:"read,optional"`
	Write      string `hcl:"write,optional"`
	Idle       string `hcl:"idle,optional"`
	ReadHeader string `hcl:"read_header,optional"`
}

// ---- HOST CONFIG ---------------------------------------------

type HostConfig struct {
	Domains []string     `hcl:"domains"` // Replaces server_names
	Routes  []Route      `hcl:"route,block"`
	Web     *Web         `hcl:"web,block"`
	TLS     *TSL         `hcl:"tls,block"`
	Limits  *LimitConfig `hcl:"limits,block"`
}

type LimitConfig struct {
	MaxBodySize int64 `hcl:"max_body_size,optional"`
}

// ---- ROUTING -------------------------------------------------

type Route struct {
	Path          string   `hcl:"path,label"`
	Backends      []string `hcl:"backends"`
	StripPrefixes []string `hcl:"strip_prefixes,optional"`
	LBStrategy    string   `hcl:"lb_strategy,optional"`
	HealthCheck   string   `hcl:"health_check,optional"`
}

// ---- STATIC WEB ----------------------------------------------

type Web struct {
	Root  WebRoot `hcl:"root"` // Typed for behavior
	Index string  `hcl:"index,optional"`
}

// WebRoot is a custom type to handle default root logic
type WebRoot string

func (w WebRoot) String() string {
	if w == "" {
		return "."
	}
	return string(w)
}

// ---- TLS -----------------------------------------------------

type TSL struct {
	Mode        TlsMode     `hcl:"mode,optional"`
	Local       LocalCert   `hcl:"local,block"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block"`
}

type LocalCert struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type LetsEncrypt struct {
	Email   string `hcl:"email,optional"`
	Staging bool   `hcl:"staging,optional"`
}

// ---- DEFAULTS ------------------------------------------------
