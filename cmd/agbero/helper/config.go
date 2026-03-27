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

	ServePath     string
	ServePort     int
	ServeBind     string
	ServeHTTPS    bool
	ServeMarkdown bool
	ServeSPA      bool
	ServePHP      string

	ProxyTarget string
	ProxyDomain string
	ProxyPort   int
	ProxyBind   string
	ProxyHTTPS  bool

	HashPassword   string
	PasswordLength string

	SystemOut   string
	SystemIn    string
	SystemPass  string
	SystemForce bool
	SystemYes   bool

	// Keeper subcommands
	KeeperKey     string
	KeeperValue   string
	KeeperB64     bool
	KeeperFile    string
	KeeperForce   bool
	KeeperUser    string
	KeeperOutFile string
}
