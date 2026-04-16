package xudp

import "strings"

// Matcher inspects the first datagram received from a new client and
// returns a stable routing key that is used to pin the session to a
// specific backend.
//
// Returning ("", false) means the matcher could not extract a key from
// this datagram — the proxy falls back to "src_ip:src_port" keying.
//
// Implementations must be safe for concurrent use and must not retain
// the data slice after Match returns.
type Matcher interface {
	// Match inspects raw datagram bytes and returns a routing key.
	Match(data []byte) (key string, ok bool)

	// Name identifies the matcher in logs and configuration.
	Name() string
}

// matcherRegistry maps matcher name → Matcher.
// Populated at init time by each protocol file (dns.go, webrtc.go, sip.go).
var matcherRegistry = map[string]Matcher{}

func registerMatcher(m Matcher) {
	matcherRegistry[strings.ToLower(m.Name())] = m
}

// lookupMatcher returns the Matcher for the given name, or nil if
// the name is empty or unknown (falls back to src:port keying).
func lookupMatcher(name string) Matcher {
	if name == "" {
		return nil
	}
	return matcherRegistry[strings.ToLower(name)]
}
