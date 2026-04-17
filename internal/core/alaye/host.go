package alaye

import (
	"net"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Host struct {
	Protected    expect.Toggle `hcl:"protected,attr" json:"protected"`
	Domains      []string      `hcl:"domains,attr" json:"domains"`
	Bind         []string      `hcl:"bind,attr" json:"bind"`
	NotFoundPage string        `hcl:"not_found_page,attr" json:"not_found_page"`
	Compression  bool          `hcl:"compression,attr" json:"compression"`

	TLS        TLS        `hcl:"tls,block,omitempty" json:"tls,omitempty"`
	Limits     Limit      `hcl:"limits,block,omitempty" json:"limits,omitempty"`
	Headers    Headers    `hcl:"headers,block,omitempty" json:"headers,omitempty"`
	ErrorPages ErrorPages `hcl:"error_pages,block,omitempty" json:"error_pages,omitempty"`

	Routes  []Route `hcl:"route,block" json:"routes"`
	Proxies []Proxy `hcl:"proxy,block" json:"proxies"`

	// source
	SourceFile string `hcl:"-" json:"source_file,omitempty"`
}

// Validate checks domains, bind ports, routes, and all nested blocks.
// It does not set defaults — call woos.DefaultHost before Validate.
func (h *Host) Validate() error {
	if len(h.Domains) == 0 {
		return def.ErrNoDomains
	}
	for i, domain := range h.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			return errors.Newf("domain [%d]: %w", i, def.ErrCannotBeEmpty)
		}
		if strings.Contains(domain, def.ProtocolSeparator) {
			return errors.Newf("domains[%d]: %q %w", i, domain, def.ErrDomainHasProtocol)
		}
		h.Domains[i] = domain
	}

	for i, port := range h.Bind {
		port = strings.TrimSpace(port)
		if port == "" {
			return errors.Newf("bind[%d]: %w", def.ErrCannotBeEmpty, i)
		}
		if strings.HasPrefix(port, ":") {
			port = port[1:]
		}
		if _, err := net.LookupPort(def.TCP, port); err != nil {
			return errors.Newf("%w-bind[%d]: %q is not a valid port", def.ErrInvalidPort, i, port)
		}
		h.Bind[i] = port
	}

	if len(h.Routes) == 0 {
		return def.ErrNoRoutes
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
