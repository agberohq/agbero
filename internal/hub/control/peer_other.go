//go:build !linux

package control

import "net"

// The socket is created with 0600 inside a 0700 data directory. Linux
// additionally verifies SO_PEERCRED; other platforms rely on filesystem
// permissions until their native peer-credential API is wired.
func peerAllowed(net.Conn) bool { return true }
