package alaye

import "time"

type TCPRoute struct {
	Status   Status    `hcl:"enabled,optional" json:"enabled"`
	Name     string    `hcl:"name,label" json:"name"`
	Listen   string    `hcl:"listen" json:"listen"`
	SNI      string    `hcl:"sni,optional" json:"sni"` // e.g. "db.internal" or "*.db.internal"
	Backends []*Server `hcl:"backend,block" json:"backends"`
	Strategy string    `hcl:"strategy,optional" json:"strategy"`

	ProxyProtocol  bool            `hcl:"proxy_protocol,optional" json:"proxy_protocol"`
	MaxConnections int64           `hcl:"max_connections,optional" json:"max_connections"`
	HealthCheck    *TCPHealthCheck `hcl:"health_check,block" json:"health_check"`
}

type TCPHealthCheck struct {
	Interval time.Duration `hcl:"interval,optional" json:"interval"`
	Timeout  time.Duration `hcl:"timeout,optional" json:"timeout"`
	Send     string        `hcl:"send,optional" json:"send"`
	Expect   string        `hcl:"expect,optional" json:"expect"`
}
