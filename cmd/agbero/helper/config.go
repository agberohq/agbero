package helper

import "time"

type Config struct {
	ConfigPath  string
	DevMode     bool
	InstallHere bool

	UninstallAll   bool
	UninstallForce bool

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
