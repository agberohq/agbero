package expect

import "regexp"

type SecretScheme string

const (
	// Standard URI Schemes
	SchemeSS     SecretScheme = "ss"
	SchemeVault  SecretScheme = "vault"
	SchemeKeeper SecretScheme = "keeper"
	SchemeCerts  SecretScheme = "certs"
	SchemeSecret SecretScheme = "secret"
	SchemeEnv    SecretScheme = "env"
	SchemeFile   SecretScheme = "file"
	SchemeSpaces SecretScheme = "spaces"

	// Dot-notation Aliases
	AliasSS     = "ss."
	AliasKeeper = "keeper."
	AliasEnv    = "env."
	AliasB64    = "b64."
)

// KeeperStorePrefixes contains all prefixes that must be resolved via the Keeper
var KeeperStorePrefixes = []string{
	string(SchemeSS) + "://",
	string(SchemeVault) + "://",
	string(SchemeKeeper) + "://",
	string(SchemeCerts) + "://",
	string(SchemeSpaces) + "://",
	AliasSS,
	AliasKeeper,
}

var (
	RegexNamespace = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	RegexSecretKey = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)
	RegexSubKey    = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
)
