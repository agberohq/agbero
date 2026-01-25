package main

import "time"

type Config struct {
	// Load test config
	Targets     []string      `json:"targets"`
	Concurrency int           `json:"concurrency"`
	Requests    int           `json:"requests"` // 0 = infinite
	Duration    time.Duration `json:"duration"`
	RateLimit   int           `json:"rate_limit"` // reqs/sec, 0 = unlimited
	Method      string        `json:"method"`
	Headers     []string      `json:"headers"`
	Body        string        `json:"body"`
	KeepAlive   bool          `json:"keep_alive"`
	Timeout     time.Duration `json:"timeout"`
	RandomIPs   bool          `json:"random_ips"`
	IPPoolSize  int           `json:"ip_pool_size"`
	OutputJSON  bool          `json:"output_json"`
	Verbose     bool          `json:"verbose"`
	Follow      bool          `json:"follow"`
	MetricsURL  string        `json:"metrics_url"`
	ShowLatency bool          `json:"show_latency"`

	// Server config
	ServeMode  bool     `json:"serve_mode"`
	Ports      []string `json:"ports"`
	StartPort  int      `json:"start_port"`
	EndPort    int      `json:"end_port"`
	TotalPorts int      `json:"total_ports"`
	PortString string   `json:"port_string"`
}

type progressMsg struct {
	completed uint64
	total     uint64
	done      bool
}

type metricsMsg struct{}

type logMsg struct {
	text string
}

type agberoMetricsMsg struct {
	metrics map[string]interface{}
}
