package alaye

import (
	"strconv"
	"strings"
)

type Backend struct {
	Enabled  Enabled  `hcl:"enabled,attr" json:"enabled"`
	Strategy string   `hcl:"strategy,attr" json:"strategy"`
	Keys     []string `hcl:"keys,attr" json:"keys"`

	Servers []Server `hcl:"server,block" json:"servers"`
}

// BackendKey provides a deterministic, zero-allocation identifier for routing observability.
// Because all fields are strings, this struct is intrinsically comparable and usable as a map key.
type BackendKey struct {
	Protocol string
	Domain   string
	Path     string
	Addr     string
}

// String is used for logging and identification, never on the hot path.
func (k BackendKey) String() string {
	return strings.Join([]string{k.Protocol, k.Domain, k.Path, k.Addr}, "|")
}

// ID is used for logging and identification, never on the hot path.
func (k BackendKey) ID(counter uint64) string {
	return strings.Join([]string{
		k.Protocol,
		k.Domain,
		k.Path,
		k.Addr,
		strconv.FormatUint(counter, 10),
	}, "|")
}
