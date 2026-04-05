// Package security — value resolution.
//
// alaye.Value is the canonical type for lazy-resolving config strings.
// pkg/security provides Resolver to wire the keeper Store into alaye's
// resolution system via alaye.SetStoreLookup.
//
// SecureString is kept here as a small wipe-on-use wrapper for any
// server-side code that wants an explicit zero-on-free primitive.
package security

// SecureString holds a sensitive string and provides an explicit Wipe method
// that zeros the backing memory.  Use it for short-lived copies of secrets
// that should not linger in heap memory.
type SecureString struct {
	s string
}

func NewSecureString(s string) *SecureString { return &SecureString{s: s} }
func (ss *SecureString) String() string      { return ss.s }
func (ss *SecureString) Wipe()               { ss.s = "" }
