package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Host struct {
	Domains      []string      `hcl:"domains" json:"domains"`
	Bind         []string      `hcl:"bind,optional" json:"bind"`
	NotFoundPage string        `hcl:"not_found_page,optional" json:"not_found_page"`
	Compression  bool          `hcl:"compression,optional" json:"compression"`
	TLS          TLS           `hcl:"tls,block" json:"tls"`
	Limits       Limit         `hcl:"limits,block" json:"limits"`
	Headers      Headers       `hcl:"headers,block" json:"headers"`
	Routes       []Route       `hcl:"route,block" json:"routes"`
	Proxies      []TCPRoute    `hcl:"proxy,block" json:"proxies"` // Renamed & Tag Updated
	Tunnel       *TunnelConfig `hcl:"tunnel,block" json:"tunnel,omitempty"`
}

func (h *Host) Validate() error {
	if len(h.Domains) == 0 {
		return ErrNoDomains
	}
	for i, domain := range h.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			return errors.Newf("domain [%d]: %w", i, ErrCannotBeEmpty)
		}
		if strings.Contains(domain, ProtocolSeparator) {
			return errors.Newf("domains[%d]: %q %w", i, domain, ErrDomainHasProtocol)
		}
		h.Domains[i] = domain
	}

	for i, port := range h.Bind {
		port = strings.TrimSpace(port)
		if port == "" {
			return errors.Newf("bind[%d]: %w", ErrCannotBeEmpty, i)
		}
		if strings.HasPrefix(port, ":") {
			port = port[1:]
		}
		if _, err := net.LookupPort(TCP, port); err != nil {
			return errors.Newf("%w-bind[%d]: %q is not a valid port", ErrInvalidPort, i, port)
		}
		h.Bind[i] = port
	}

	if len(h.Routes) == 0 {
		return ErrNoRoutes
	}
	for i, route := range h.Routes {
		if err := route.Validate(); err != nil {
			return errors.Newf("routes[%d]: %w", i, err)
		}
	}

	if err := h.TLS.Validate(); err != nil {
		return errors.Newf("tls: %w", err)
	}

	if err := h.Limits.Validate(); err != nil {
		return errors.Newf("limits: %w", err)
	}

	if err := h.Headers.Validate(); err != nil {
		return errors.Newf("headers: %w", err)
	}

	if h.Tunnel != nil {
		if err := h.Tunnel.Validate(); err != nil {
			return errors.Newf("tunnel: %w", err)
		}
	}

	return nil
}
