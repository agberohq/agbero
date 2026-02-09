package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Host struct {
	Domains      []string      `hcl:"domains" json:"domains"`
	Bind         []string      `hcl:"bind,optional" json:"bind"`
	Compression  bool          `hcl:"compression,optional" json:"compression"`
	Routes       []Route       `hcl:"route,block" json:"routes"`
	TLS          TLS           `hcl:"tls,block" json:"tls"`
	Limits       Limit         `hcl:"limits,block" json:"limits"`
	Headers      Headers       `hcl:"headers,block" json:"headers"`
	TCPProxy     []TCPRoute    `hcl:"tcp_proxy,block" json:"tcp_proxy"`
	Tunnel       *TunnelConfig `hcl:"tunnel,block" json:"tunnel,omitempty"`
	NotFoundPage string        `hcl:"not_found_page,optional" json:"not_found_page"`
}

func (h *Host) Validate() error {
	// Domains validation
	if len(h.Domains) == 0 {
		return ErrNoDomains
	}
	for i, domain := range h.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			return errors.Newf("domain [%d]: %w", i, ErrCannotBeEmpty)
		}
		// Basic domain validation
		if strings.Contains(domain, ProtocolSeparator) {
			return errors.Newf("domains[%d]: %q %w", i, domain, ErrDomainHasProtocol)
		}
		h.Domains[i] = domain // Normalize
	}

	// Bind ports validation (if provided)
	for i, port := range h.Bind {
		port = strings.TrimSpace(port)
		if port == "" {
			return errors.Newf("bind[%d]: %w", ErrCannotBeEmpty, i)
		}
		// Normalize ":3000" to "3000"
		if strings.HasPrefix(port, ":") {
			port = port[1:]
		}
		if _, err := net.LookupPort(TCP, port); err != nil {
			return errors.Newf("%w-bind[%d]: %q is not a valid port", ErrInvalidPort, i, port)
		}
		h.Bind[i] = port
	}

	// Routes validation
	if len(h.Routes) == 0 {
		return ErrNoRoutes
	}
	for i, route := range h.Routes {
		if err := route.Validate(); err != nil {
			return errors.Newf("routes[%d]: %w", i, err)
		}
	}

	// TLS validation
	if err := h.TLS.Validate(); err != nil {
		return errors.Newf("tls: %w", err)
	}

	// Limits validation
	if err := h.Limits.Validate(); err != nil {
		return errors.Newf("limits: %w", err)
	}

	// Headers validation
	if err := h.Headers.Validate(); err != nil {
		return errors.Newf("headers: %w", err)
	}

	// Tunnel validation
	if h.Tunnel != nil {
		if err := h.Tunnel.Validate(); err != nil {
			return errors.Newf("tunnel: %w", err)
		}
	}

	return nil
}
