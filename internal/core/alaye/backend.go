package alaye

import "strings"

type Backend struct {
	Enabled  Enabled `hcl:"enabled,optional" json:"enabled"`
	Strategy string  `hcl:"strategy,optional" json:"strategy"`

	// Keys defines the priority list for extracting values for sticky sessions or consistent hashing.
	// Examples: "cookie:session_id", "header:Authorization", "query:id", "ip"
	Keys []string `hcl:"keys,optional" json:"keys"`

	Servers []Server `hcl:"server,block" json:"servers"`
}

// BackendKey provides a deterministic, zero-allocation identifier for routing observability.
// Because all fields are strings, this struct is intrinsically comparable and perfect for map keys.
type BackendKey struct {
	Protocol string
	Domain   string
	Path     string
	Addr     string
}

// String is used for logging and patient identification, but NEVER called on the hot path.
func (k BackendKey) String() string {
	return strings.Join([]string{k.Protocol, k.Domain, k.Path, k.Addr}, "|")
}
