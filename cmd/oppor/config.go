package main

import (
	"fmt"
	"strings"
	"time"
)

type LoadConfig struct {
	Targets     []string
	Concurrency int
	Requests    int
	Duration    time.Duration
	RateLimit   int
	Method      string
	Headers     map[string]string
	Body        string
	Timeout     time.Duration
}

type ServerConfig struct {
	Port           string
	PortRange      string
	Speed          string
	FailureRate    float64
	BaseLatency    time.Duration
	Jitter         time.Duration
	ResponseSize   string
	FailureCodes   []int
	FailurePattern string
	ContentMode    string
	SlowEndpoint   string
	CPULoad        float64
	MemoryPerReq   int
	SessionMode    string
	CacheHitRate   float64
	TLSCert        string
	TLSKey         string
}

func (c ServerConfig) Validate() error {
	if c.FailureRate < 0 || c.FailureRate > 1 {
		return fmt.Errorf("failure rate must be between 0 and 1")
	}
	if c.CacheHitRate < 0 || c.CacheHitRate > 1 {
		return fmt.Errorf("cache hit rate must be between 0 and 1")
	}
	if c.CPULoad < 0 || c.CPULoad > 1 {
		return fmt.Errorf("CPU load must be between 0 and 1")
	}
	return nil
}

func (c LoadConfig) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target required")
	}
	for _, t := range c.Targets {
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			return fmt.Errorf("invalid target URL: %s", t)
		}
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be > 0")
	}
	if c.Requests < 0 {
		return fmt.Errorf("requests cannot be negative")
	}
	return nil
}
