// Package safedial provides a DialContext implementation that prevents
// Server-Side Request Forgery (SSRF) attacks by blocking outbound connections
// to private, loopback, and link-local IP addresses after DNS resolution but
// before the TCP socket opens.
//
// Using this dialer is the only correct way to prevent DNS-rebinding SSRF in
// Go's net/http: a pre-dial IP check (e.g. in a validation function) and the
// actual dial are two separate operations, giving an attacker a TOCTOU window
// to switch the DNS response between the check and the connection. This dialer
// resolves the hostname itself and dials the resolved IP directly, collapsing
// check and dial into a single atomic step.
package safedial

import (
	"context"
	"fmt"
	"net"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// DialContextFunc is the signature accepted by http.Transport.DialContext.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// New returns a DialContext function that wraps d and rejects connections to
// private, loopback, link-local, and unspecified IP addresses.
//
// prefix is prepended to error messages to identify the caller in logs
// (e.g. "backend", "forward_auth"). It should be a short lowercase label.
//
// How it eliminates the TOCTOU / DNS-rebinding window:
//  1. net/http calls DialContext with the original hostname.
//  2. We resolve it ourselves and check every returned address.
//  3. We dial the specific resolved IP directly — no second DNS lookup occurs.
func New(d *net.Dialer, prefix string) DialContextFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid address %q: %w", prefix, addr, err)
		}

		// Raw IP supplied directly (net/http occasionally does this).
		// Validate without a DNS round-trip.
		if ip := net.ParseIP(host); ip != nil {
			if alaye.IsPrivateIP(ip) {
				return nil, fmt.Errorf(
					"%s: SSRF protection blocked connection to private/internal address %s:%s",
					prefix, host, port,
				)
			}
			return d.DialContext(ctx, network, addr)
		}

		// Hostname path: resolve, check every returned address, then dial the
		// specific resolved IP so no second lookup can occur.
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%s: DNS resolution failed for %q: %w", prefix, host, err)
		}

		var lastErr error
		for _, a := range addrs {
			resolved := net.ParseIP(a)
			if resolved == nil {
				continue
			}

			// If any resolved address for this hostname is private, treat the
			// whole hostname as untrustworthy and abort immediately rather than
			// silently skipping to a "safe" address — a hostname that resolves
			// to a private IP under any circumstance is exactly the DNS-rebinding
			// pattern this dialer exists to catch.
			if alaye.IsPrivateIP(resolved) {
				return nil, fmt.Errorf(
					"%s: SSRF protection blocked connection to private/internal address %s (resolved from %s)",
					prefix, a, host,
				)
			}

			// Dial the resolved IP directly — atomic check+dial prevents rebind.
			conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(a, port))
			if dialErr == nil {
				return conn, nil
			}
			// This address is public but unreachable (connection refused,
			// timeout, etc.) — fall through to try the next A/AAAA record,
			// matching standard net/http DNS-failover behaviour.
			lastErr = dialErr
		}
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("%s: no valid public address resolved for %q", prefix, host)
	}
}
