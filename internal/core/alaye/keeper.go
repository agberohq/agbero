package alaye

import "github.com/agberohq/agbero/internal/core/expect"

type Keeper struct {
	// Enabled indicates whether the secret store is active.
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`

	// Logging specifies whether logging is enabled or disabled for the secret store.
	Logging expect.Toggle `hcl:"logging,attr" json:"logging"`

	// AutoLock is the duration after which the store auto-locks when idle (0 = disabled).
	AutoLock expect.Duration `hcl:"auto_lock,attr" json:"auto_lock"`

	// Audit enables audit logging of all secret access (get/set/delete).
	Audit expect.Toggle `hcl:"audit,attr" json:"audit"`

	// Passphrase is the master passphrase to unlock the store.
	// This should be a secret reference (e.g., "env.SECRET_STORE_PASS") to avoid plaintext.
	Passphrase expect.Value `hcl:"passphrase,attr" json:"passphrase"` // can later be *security.Value

	// PassphraseFile points at a file containing the master passphrase.
	// It is the portable delivery mechanism for services: no secret in the
	// unit file, registry, or environment. Resolution order is
	// Passphrase -> PassphraseFile -> AGBERO_KEEPER_PASSPHRASE ->
	// AGBERO_PASSPHRASE -> interactive prompt.
	PassphraseFile string `hcl:"passphrase_file,attr" json:"passphrase_file"`
}
