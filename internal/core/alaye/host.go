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

	// Relays configure the remote end of Agbero-to-Agbero reverse tunnels.
	// Agents configure the local outbound end.
	Relays []Relay `hcl:"relay,block" json:"relays,omitempty"`
	Agents []Agent `hcl:"agent,block" json:"agents,omitempty"`

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
		// A domain becomes a filename component (hosts.d/<domain>.hcl) and an
		// in-memory index key. Path separators and parent references must never
		// reach either — see discovery.sanitizeHostFilename for the filesystem
		// side of this defence.
		if strings.ContainsAny(domain, `/\`) || strings.Contains(domain, "..") {
			return errors.Newf("domains[%d]: %q must not contain path separators or \"..\"", i, domain)
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

	// A remote relay endpoint may exist only to accept agents; it does not need
	// a local route. Every other host still needs at least one route.
	if len(h.Routes) == 0 && len(h.Relays) == 0 {
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

	seenRelays := make(map[string]bool, len(h.Relays))
	for i := range h.Relays {
		if err := h.Relays[i].Validate(); err != nil {
			return errors.Newf("relays[%d]: %w", i, err)
		}
		if seenRelays[h.Relays[i].Name] {
			return errors.Newf("relays[%d]: duplicate name %q", i, h.Relays[i].Name)
		}
		seenRelays[h.Relays[i].Name] = true
	}

	seenAgents := make(map[string]bool, len(h.Agents))
	for i := range h.Agents {
		if err := h.Agents[i].Validate(); err != nil {
			return errors.Newf("agents[%d]: %w", i, err)
		}
		if seenAgents[h.Agents[i].Name] {
			return errors.Newf("agents[%d]: duplicate name %q", i, h.Agents[i].Name)
		}
		seenAgents[h.Agents[i].Name] = true
	}
	for i := range h.Routes {
		for j := range h.Routes[i].Exposes {
			ex := &h.Routes[i].Exposes[j]
			if !seenAgents[ex.Via] {
				return errors.Newf("route %q: expose %q references unknown agent %q", h.Routes[i].Path, ex.ID, ex.Via)
			}
		}
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
