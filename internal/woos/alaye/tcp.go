package alaye

import "time"

type TCPRoute struct {
	Listen   string   `hcl:"listen" json:"listen"`
	Backends []Server `hcl:"backend,block" json:"backends"`
	Strategy string   `hcl:"strategy,optional" json:"strategy"`

	// Security & Protocol (Service Level)
	ProxyProtocol bool `hcl:"proxy_protocol,optional" json:"proxy_protocol"`

	// Stability (Global Limits)
	MaxConnections int64 `hcl:"max_connections,optional" json:"max_connections"`

	// Reliability
	HealthCheck *TCPHealthCheck `hcl:"health_check,block" json:"health_check"`
}

type TCPHealthCheck struct {
	Interval time.Duration `hcl:"interval,optional" json:"interval"`
	Timeout  time.Duration `hcl:"timeout,optional" json:"timeout"`
	Send     string        `hcl:"send,optional" json:"send"`     // e.g. "PING\r\n"
	Expect   string        `hcl:"expect,optional" json:"expect"` // e.g. "PONG"
}
