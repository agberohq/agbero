package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Host struct {
	Domains     []string   `hcl:"domains"`
	Bind        []string   `hcl:"bind,optional"`
	Compression bool       `hcl:"compression,optional"`
	Routes      []Route    `hcl:"route,block"`
	TLS         TLS        `hcl:"tls,block"`
	Limits      Limit      `hcl:"limits,block"`
	Headers     Headers    `hcl:"headers,block"`
	TCPProxy    []TCPRoute `hcl:"tcp_proxy,block"`
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
		if strings.Contains(domain, "://") {
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
		if _, err := net.LookupPort("tcp", port); err != nil {
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
	Listen   string   `hcl:"listen"`
	Backends []Server `hcl:"backend,block"`
	Strategy string   `hcl:"strategy,optional"` // round_robin, least_conn, random
}
