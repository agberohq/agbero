package helper

import "time"

type Config struct {
	ConfigPath  string
	DevMode     bool
	InstallHere bool

	// UninstallForce: skip confirmation prompt AND remove the binary.
	// Without --force the confirmation is always shown and the binary is kept.
	UninstallAll   bool
	UninstallForce bool

	KeyService string
	KeyTTL     time.Duration

	ForceCAInstall bool
	CertDir        string
	CertDomain     string // domain argument for cert delete

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

	KeeperKey     string
	KeeperValue   string
	KeeperB64     bool
	KeeperFile    string
	KeeperForce   bool
	KeeperUser    string
	KeeperOutFile string

	AdminPassword string
}
