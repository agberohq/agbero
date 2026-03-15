package helper

import (
	"time"

	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type Config struct {
	ConfigPath  string
	DevMode     bool
	InstallHere bool

	KeyService string
	KeyTTL     time.Duration

	ForceCAInstall bool
	CertDir        string

	ClusterJoinIP string
	ClusterSecret string

	ServePath  string
	ServePort  int
	ServeBind  string
	ServeHTTPS bool

	ProxyTarget string
	ProxyDomain string
	ProxyPort   int
	ProxyBind   string
	ProxyHTTPS  bool

	HashPassword   string
	PasswordLength string
}

type Helper struct {
	Logger   *ll.Logger
	Shutdown *jack.Shutdown
	Cfg      *Config
}

func New(logger *ll.Logger, shutdown *jack.Shutdown, cfg *Config) *Helper {
	return &Helper{
		Logger:   logger,
		Shutdown: shutdown,
		Cfg:      cfg,
	}
}

func (h *Helper) Config() *ConfigHelper   { return &ConfigHelper{p: h} }
func (h *Helper) Secret() *SecretHelper   { return &SecretHelper{p: h} }
func (h *Helper) Host() *HostHelper       { return &HostHelper{p: h} }
func (h *Helper) Cert() *CertHelper       { return &CertHelper{p: h} }
func (h *Helper) Service() *ServiceHelper { return &ServiceHelper{p: h} }
func (h *Helper) Cluster() *ClusterHelper { return &ClusterHelper{p: h} }
func (h *Helper) Home() *HomeHelper       { return &HomeHelper{p: h} }
func (h *Helper) Ephemeral() *EphemeralHelper {
	return &EphemeralHelper{p: h}
}
