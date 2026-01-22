package config

const (
	Name        = "agbero"
	Version     = "0.0.1"
	Description = "Production reverse proxy with Let's Encrypt 2026 support"
)

const (
	StrategyRandom    = "random"
	StrategyLeastConn = "leastconn"
)

const (
	DefaultScanInterval = 5
)

type TlsMode string

const (
	ModeLocalNone   TlsMode = "none"
	ModeLocalCert   TlsMode = "local"
	ModeLetsEncrypt TlsMode = "letsencrypt"
)
