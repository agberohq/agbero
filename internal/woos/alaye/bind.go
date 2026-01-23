package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Bind struct {
	HTTP    []string `hcl:"http,optional"`
	HTTPS   []string `hcl:"https,optional"`
	Metrics string   `hcl:"metrics,optional"`
}

func (b *Bind) Validate() error {
	// At least one listener must be configured
	if len(b.HTTP) == 0 && len(b.HTTPS) == 0 {
		return errors.New("at least one of 'http' or 'https' bind addresses must be configured")
	}

	// Validate HTTP addresses
	for i, addr := range b.HTTP {
		if addr == "" {
			return errors.Newf("http[%d]: address cannot be empty", i)
		}
		if err := b.validateAddress(addr); err != nil {
			return errors.Newf("http[%d]: %w", i, err)
		}
	}

	// Validate HTTPS addresses
	for i, addr := range b.HTTPS {
		if addr == "" {
			return errors.Newf("https[%d]: address cannot be empty", i)
		}
		if err := b.validateAddress(addr); err != nil {
			return errors.Newf("https[%d]: %w", i, err)
		}
	}

	// Validate metrics address (if provided)
	if b.Metrics != "" {
		if err := b.validateAddress(b.Metrics); err != nil {
			return errors.Newf("metrics: %w", err)
		}
	}

	return nil
}

func (b *Bind) validateAddress(addr string) error {
	if addr == "" {
		return errors.New("address cannot be empty")
	}

	// Check if it's just a port
	if strings.HasPrefix(addr, ":") {
		port := addr[1:]
		if _, err := net.LookupPort("tcp", port); err != nil {
			return errors.Newf("invalid port %q: %w", port, err)
		}
		return nil
	}

	// Check if it's host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.Newf("invalid address %q: %w", addr, err)
	}

	// Validate host
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			// Not an IP, check if it's a valid hostname
			if strings.Contains(host, "://") {
				return errors.New("address should not include protocol")
			}
		}
	}

	// Validate port
	if _, err := net.LookupPort("tcp", port); err != nil {
		return errors.Newf("invalid port %q: %w", port, err)
	}

	return nil
}
