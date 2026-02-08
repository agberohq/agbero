package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Host struct {
	Domains      []string   `hcl:"domains" json:"domains"`
	Bind         []string   `hcl:"bind,optional" json:"bind"`
	Compression  bool       `hcl:"compression,optional" json:"compression"`
	Routes       []Route    `hcl:"route,block" json:"routes"`
	TLS          TLS        `hcl:"tls,block" json:"tls"`
	Limits       Limit      `hcl:"limits,block" json:"limits"`
	Headers      Headers    `hcl:"headers,block" json:"headers"`
	TCPProxy     []TCPRoute `hcl:"tcp_proxy,block" json:"tcp_proxy"`
	NotFoundPage string     `hcl:"not_found_page,optional" json:"not_found_page"` // New: Custom 404
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

	return nil
}

type TCPRoute struct {
	Listen   string   `hcl:"listen" json:"listen"`
	Backends []Server `hcl:"backend,block" json:"backends"`
	Strategy string   `hcl:"strategy,optional" json:"strategy"` // round_robin, least_conn, random
}

// TunnelConfig holds configuration for FRP integrations.
type TunnelConfig struct {
	Server *TunnelServer `hcl:"server,block" json:"server,omitempty"`
	Client *TunnelClient `hcl:"client,block" json:"client,omitempty"`
	Router *TunnelRouter `hcl:"router,block" json:"router,omitempty"`
}

type TunnelServer struct {
	Enabled bool `hcl:"enabled" json:"enabled"`
	// Additional FRP server settings
}

type TunnelClient struct {
	Enabled   bool              `hcl:"enabled" json:"enabled"`
	Server    string            `hcl:"server" json:"server"`       // wss://tunnel.agbero.com/_connect
	Subdomain string            `hcl:"subdomain" json:"subdomain"` // e.g. "blog"
	Headers   map[string]string `hcl:"headers,optional" json:"headers"`
}

type TunnelRouter struct {
	Enabled bool `hcl:"enabled" json:"enabled"`
	// This tells Agbero to look up FRP proxies for this host
}
