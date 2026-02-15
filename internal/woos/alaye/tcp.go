package alaye

import (
	"net"
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type TCPRoute struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Name     string   `hcl:"name,label" json:"name"`
	Listen   string   `hcl:"listen" json:"listen"`
	SNI      string   `hcl:"sni,optional" json:"sni"`
	Backends []Server `hcl:"backend,block" json:"backends"`
	Strategy string   `hcl:"strategy,optional" json:"strategy"`

	ProxyProtocol  bool           `hcl:"proxy_protocol,optional" json:"proxy_protocol"`
	MaxConnections int64          `hcl:"max_connections,optional" json:"max_connections"`
	HealthCheck    TCPHealthCheck `hcl:"health_check,block" json:"health_check"`
}

func (t *TCPRoute) Validate() error {
	if t.Enabled.No() {
		return nil
	}

	switch {
	case t.Name == "":
		return errors.New("route name required")
	case t.Listen == "":
		return errors.New("listen address required")
	case len(t.Backends) == 0:
		return errors.New("at least one backend required")
	}

	// Validate listen address format
	if _, _, err := net.SplitHostPort(t.Listen); err != nil {
		return errors.Newf("invalid listen address %q: %w", t.Listen, err)
	}

	// Validate SNI pattern if provided
	if t.SNI != "" {
		if strings.Contains(t.SNI, "..") ||
			strings.HasPrefix(t.SNI, ".") ||
			strings.HasSuffix(t.SNI, ".") {
			return errors.Newf("invalid SNI pattern %q", t.SNI)
		}
		// Only allow leading wildcard
		if strings.Contains(t.SNI, "*") && !strings.HasPrefix(t.SNI, "*.") {
			return errors.Newf("invalid wildcard in SNI %q: only leading *. allowed", t.SNI)
		}
	}

	// Validate strategy
	if t.Strategy != "" && !ValidateStrategy(t.Strategy) {
		return errors.Newf("invalid strategy %q", t.Strategy)
	}

	if t.MaxConnections < 0 {
		return errors.New("max_connections cannot be negative")
	}

	// Validate backends
	for i := range t.Backends {
		if err := t.Backends[i].Validate(); err != nil {
			return errors.Newf("backend[%d]: %w", i, err)
		}
	}

	return t.HealthCheck.Validate()
}

type TCPHealthCheck struct {
	Enabled  Enabled       `hcl:"enabled,optional" json:"enabled"`
	Interval time.Duration `hcl:"interval,optional" json:"interval"`
	Timeout  time.Duration `hcl:"timeout,optional" json:"timeout"`
	Send     string        `hcl:"send,optional" json:"send"`
	Expect   string        `hcl:"expect,optional" json:"expect"`
}

func (t *TCPHealthCheck) Validate() error {
	if t.Enabled.No() {
		return nil
	}

	switch {
	case t.Interval < 0:
		return errors.New("health_check.interval cannot be negative")
	case t.Timeout < 0:
		return errors.New("health_check.timeout cannot be negative")
	case t.Interval > 0 && t.Timeout >= t.Interval:
		// Warning only, not an error
	}

	return nil
}
