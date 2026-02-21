package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/integrii/flaggy"
)

var version = "3.0.0"

func main() {
	flaggy.SetName("oppor")
	flaggy.SetDescription("Production-grade load tester & test server for load balancers")
	flaggy.SetVersion(version)

	var interactive bool
	flaggy.Bool(&interactive, "i", "interactive", "Interactive mode")

	// Server subcommand
	serverCmd := flaggy.NewSubcommand("serve")
	var port, portRange, speed string
	var baseLatency, jitter time.Duration
	var failureRate float64
	var failureCodes, failurePattern, contentMode, responseSize, slowEndpoint string
	var cpuLoad float64
	var memoryPerReq int
	var sessionMode string
	var cacheHitRate float64
	var tlsCert, tlsKey string

	serverCmd.String(&port, "p", "port", "Port to listen on")
	serverCmd.String(&portRange, "r", "range", "Port range (e.g. 8000-8010)")
	serverCmd.String(&speed, "s", "speed", "fast|normal|slow|erratic")
	serverCmd.Duration(&baseLatency, "l", "latency", "Base latency (e.g. 5ms)")
	serverCmd.Duration(&jitter, "j", "jitter", "Latency jitter (e.g. 10ms)")
	serverCmd.Float64(&failureRate, "f", "failure-rate", "Failure rate (0.0-1.0)")
	serverCmd.String(&failureCodes, "fc", "failure-codes", "Comma-separated codes (e.g. 500,503)")
	serverCmd.String(&failurePattern, "fp", "failure-pattern", "random|periodic|burst")
	serverCmd.String(&contentMode, "c", "content-mode", "static|dynamic|streaming")
	serverCmd.String(&responseSize, "b", "body-size", "1KB|10KB|100KB|1MB|10MB")
	serverCmd.String(&slowEndpoint, "slow", "slow-endpoint", "Path for slow responses")
	serverCmd.Float64(&cpuLoad, "cpu", "cpu-load", "CPU load simulation (0.0-1.0)")
	serverCmd.Int(&memoryPerReq, "mem", "memory-per-req", "Memory MB per request")
	serverCmd.String(&sessionMode, "session", "session-mode", "none|sticky")
	serverCmd.Float64(&cacheHitRate, "cache", "cache-hit-rate", "Cache hit rate (0.0-1.0)")
	serverCmd.String(&tlsCert, "tls-cert", "", "TLS certificate file")
	serverCmd.String(&tlsKey, "tls-key", "", "TLS key file")

	flaggy.AttachSubcommand(serverCmd, 1)

	// Load test subcommand
	runCmd := flaggy.NewSubcommand("run")
	var targets []string
	var concurrency int
	var requests int
	var duration string
	var rateLimit int
	var method string
	var headers []string
	var body string
	var timeout string

	runCmd.StringSlice(&targets, "t", "target", "Target URLs (required)")
	runCmd.Int(&concurrency, "c", "concurrency", "Number of workers")
	runCmd.Int(&requests, "n", "requests", "Total requests (0 = infinite)")
	runCmd.String(&duration, "d", "duration", "Test duration (e.g. 30s, 5m)")
	runCmd.Int(&rateLimit, "r", "rate", "Rate limit (req/sec)")
	runCmd.String(&method, "X", "method", "HTTP method")
	runCmd.StringSlice(&headers, "H", "header", "Custom headers (Key:Value)")
	runCmd.String(&body, "b", "body", "Request body")
	runCmd.String(&timeout, "timeout", "", "Request timeout")

	flaggy.AttachSubcommand(runCmd, 1)

	flaggy.Parse()

	if interactive {
		runInteractive()
		return
	}

	if serverCmd.Used {
		cfg := ServerConfig{
			Port:           port,
			PortRange:      portRange,
			Speed:          speed,
			BaseLatency:    baseLatency,
			Jitter:         jitter,
			FailureRate:    failureRate,
			FailurePattern: failurePattern,
			ContentMode:    contentMode,
			ResponseSize:   responseSize,
			SlowEndpoint:   slowEndpoint,
			CPULoad:        cpuLoad,
			MemoryPerReq:   memoryPerReq,
			SessionMode:    sessionMode,
			CacheHitRate:   cacheHitRate,
			TLSCert:        tlsCert,
			TLSKey:         tlsKey,
		}

		if failureCodes != "" {
			for _, c := range strings.Split(failureCodes, ",") {
				if code, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
					cfg.FailureCodes = append(cfg.FailureCodes, code)
				}
			}
		}

		if err := runServer(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if runCmd.Used {
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "Error: No targets specified. Use -t flag.")
			flaggy.ShowHelpAndExit("")
		}

		headerMap := make(map[string]string)
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		// Set defaults
		if concurrency == 0 {
			concurrency = 10
		}
		if method == "" {
			method = "GET"
		}
		if timeout == "" {
			timeout = "30s"
		}

		dur, _ := time.ParseDuration(duration)
		to, _ := time.ParseDuration(timeout)

		cfg := LoadConfig{
			Targets:     targets,
			Concurrency: concurrency,
			Requests:    requests,
			Duration:    dur,
			RateLimit:   rateLimit,
			Method:      method,
			Headers:     headerMap,
			Body:        body,
			Timeout:     to,
		}

		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		runLoadTest(cfg)
		return
	}

	flaggy.ShowHelpAndExit("")
}
