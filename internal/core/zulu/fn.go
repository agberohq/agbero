package zulu

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/cespare/xxhash/v2"
	"github.com/r3labs/diff/v3"
)

func NormalizeHost(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(hostport)
}

func ServerKey(addr string, tls bool) string {
	if tls {
		return woos.SchemeHTTPS + addr
	}
	return woos.SchemeHTTP + addr
}

func IsServerKeyTLS(key string) bool {
	return strings.HasPrefix(key, woos.SchemeHTTPS)
}

func NormalizeSubject(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, woos.Dot)
	s = strings.ToLower(s)

	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}

	s = strings.TrimPrefix(s, woos.IPv6BracketOpen)
	s = strings.TrimSuffix(s, woos.IPv6BracketClose)

	return s
}

func Or[T comparable](a ...T) T {
	var zero T
	for _, v := range a {
		if v != zero {
			return v
		}
	}
	return zero
}

// Debounce returns a function that calls f only after delay since last call
func Debounce(delay time.Duration, f func()) func() {
	var timer *time.Timer
	return func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(delay, f)
	}
}

// Truncate truncates the user agent string to a specified max length and appends "..." if truncation occurs.
func Truncate(ua string, maxLen int) string {
	if len(ua) <= maxLen {
		return ua
	}
	return ua[:maxLen] + "..."
}

func Diff(old, new any) []string {
	var changes []string
	changelog, _ := diff.Diff(old, new)
	for _, change := range changelog {
		path := strings.Join(change.Path, ".")
		changes = append(changes, fmt.Sprintf("%s: %v → %v", path, change.From, change.To))
	}
	return changes
}

func CutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

func PortFree() int {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")
	l, _ := net.ListenTCP("tcp", addr)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func PortScan(bindHost string, port, maxPortRetries int) (int, error) {
	bindHost = Or(bindHost, "0.0.0.0")
	startPort := port
	if startPort == 0 {
		startPort = 1024
	}

	for i := range maxPortRetries {
		port := startPort + i
		addr := fmt.Sprintf("%s:%d", bindHost, port)

		listener, err := net.Listen("tcp", addr)
		if err == nil {
			_ = listener.Close()
			return port, nil
		}

		// Only warn on specific bind errors or first attempt
		if i == 0 {
			fmt.Printf("Warning: Port %d is busy, trying next available...\n", port)
		}
	}

	return 0, fmt.Errorf("failed to find a free port on %s after %d attempts", bindHost, maxPortRetries)
}

func XXHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(
		(*[8]byte)(unsafe.Pointer(&[1]uint64{xxhash.Sum64(data)}))[:],
	)
}
