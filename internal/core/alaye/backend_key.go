package alaye

import (
	"strconv"
	"strings"
)

// Key provides a deterministic, zero-allocation identifier for routing observability.
// Because all fields are strings, this struct is intrinsically comparable and usable as a map key.
type Key struct {
	Protocol string
	Domain   string
	Path     string
	Addr     string
}

// String is used for logging and identification, never on the hot path.
func (k Key) String() string {
	return strings.Join([]string{k.Protocol, k.Domain, k.Path, k.Addr}, "|")
}

// ID is used for logging and identification, never on the hot path.
func (k Key) ID(counter uint64) string {
	return strings.Join([]string{
		k.Protocol,
		k.Domain,
		k.Path,
		k.Addr,
		strconv.FormatUint(counter, 10),
	}, "|")
}
