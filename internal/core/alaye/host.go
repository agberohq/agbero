package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Host struct {
	Protected    Enabled  `hcl:"protected,attr" json:"protected"`
	Domains      []string `hcl:"domains,attr" json:"domains"`
	Bind         []string `hcl:"bind,attr" json:"bind"`
	NotFoundPage string   `hcl:"not_found_page,attr" json:"not_found_page"`
	Compression  bool     `hcl:"compression,attr" json:"compression"`

	TLS        TLS        `hcl:"tls,block" json:"tls"`
	Limits     Limit      `hcl:"limits,block" json:"limits"`
	Headers    Headers    `hcl:"headers,block" json:"headers"`
	ErrorPages ErrorPages `hcl:"error_pages,block" json:"error_pages"`

	Routes  []Route `hcl:"route,block" json:"routes"`
	Proxies []Proxy `hcl:"proxy,block" json:"proxies"`

	// source
	SourceFile string `hcl:"-" json:"source_file,omitempty"`
}

// Validate checks domains, bind ports, routes, and all nested blocks.
// It does not set defaults — call woos.DefaultHost before Validate.
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
	if err := h.ErrorPages.Validate(); err != nil {
		return errors.Newf("host error_pages: %w", err)
	}

	return nil
}
