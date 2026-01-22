package config

// ---- GLOBAL CONFIG -------------------------------------------

type GlobalConfig struct {
	Bind        string `hcl:"bind"`                 // e.g. ":80 :443"
	HostsDir    string `hcl:"hosts_dir"`            // e.g. "./hosts.d"
	LEEmail     string `hcl:"le_email,optional"`    // required for letsencrypt
	LogLevel    string `hcl:"log_level,optional"`   // info|debug|warn|error
	Development bool   `hcl:"development,optional"` // dev mode (LE staging)
}

// ---- HOST CONFIG ---------------------------------------------

type HostConfig struct {
	Domains []string `hcl:"server_names"` // explicit domains only
	Routes  []Route  `hcl:"route,block"`
	Web     *Web     `hcl:"web,block"`
	TLS     *TSL     `hcl:"tls,block"`
}

// ---- ROUTING -------------------------------------------------

type Route struct {
	Path          string   `hcl:"path,label"`
	Backends      []string `hcl:"backends"`
	StripPrefixes []string `hcl:"strip_prefixes,optional"`
	LBStrategy    string   `hcl:"lb_strategy,optional"` // roundrobin|leastconn|random
	HealthCheck   string   `hcl:"health_check,optional"`
}

// ---- STATIC WEB ----------------------------------------------

type Web struct {
	Root  string `hcl:"root"`
	Index string `hcl:"index,optional"` // default: index.html
}

// ---- TLS -----------------------------------------------------

type TSL struct {
	Mode        TlsMode     `hcl:"mode,optional"` // none|local|letsencrypt
	Local       LocalCert   `hcl:"local,block"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block"`
}

type LocalCert struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type LetsEncrypt struct {
	Email        string `hcl:"email,optional"`         // overrides global if set
	Staging      bool   `hcl:"staging,optional"`       // per-host override
	DNSChallenge string `hcl:"dns_challenge,optional"` // future
	IPAddress    bool   `hcl:"ip_address,optional"`    // future (6-day only)
}
