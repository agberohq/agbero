package xhttp

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// sharedHTTPClient is used across all HTTP patients to avoid connection exhaustion.
// Transport is configured for high-throughput health checks with connection reuse.
var sharedHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// RegisterHTTPPatients creates a Patient for each backend server in the route.
// Configured for high-throughput scenarios with fast failure detection and recovery.
func RegisterHTTPPatients(domain string, route *alaye.Route, doc *jack.Doctor, registry *metrics.Registry, logger *ll.Logger) int {
	if route.Backends.Enabled.NotActive() || len(route.Backends.Servers) == 0 {
		logger.Fields("domain", domain, "route", route.Path).Debug("http backends disabled or empty")
		return 0
	}

	probeCfg := health.DefaultProbeConfig()
	if route.HealthCheck.Path != "" {
		probeCfg.Path = route.HealthCheck.Path
	}
	if route.HealthCheck.Interval > 0 {
		probeCfg.StandardInterval = route.HealthCheck.Interval
	}
	if route.HealthCheck.Timeout > 0 {
		probeCfg.Timeout = route.HealthCheck.Timeout
	}

	count := 0
	for _, srv := range route.Backends.Servers {
		statsKey := route.BackendKey(domain, srv.Address)
		score := health.GlobalRegistry.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

		u, err := url.Parse(srv.Address)
		if err != nil {
			logger.Fields("domain", domain, "server", srv.Address, "error", err).Warn("failed to parse backend url")
			continue
		}

		targetURL := u.ResolveReference(&url.URL{Path: probeCfg.Path}).String()

		headers := http.Header{}
		hostHeader := ""
		for k, v := range route.HealthCheck.Headers {
			if k == "Host" {
				hostHeader = v
			} else {
				headers.Set(k, v)
			}
		}
		if hostHeader == "" && domain != "" && domain != "*" {
			hostHeader = domain
		}

		executor := &HTTPExecutor{
			URL:            targetURL,
			Method:         route.HealthCheck.Method,
			Client:         sharedHTTPClient,
			Header:         headers,
			Host:           hostHeader,
			ExpectedStatus: route.HealthCheck.ExpectedStatus,
			ExpectedBody:   route.HealthCheck.ExpectedBody,
		}

		patient := jack.NewPatient(jack.PatientConfig{
			ID:       statsKey.String(),
			Interval: probeCfg.StandardInterval,
			Timeout:  probeCfg.Timeout,
			Check: func(ctx context.Context) error {
				success, latency, err := executor.Probe(ctx)
				score.Update(health.Record{
					ProbeLatency: latency,
					ProbeSuccess: success,
					ConnHealth:   100,
					PassiveRate:  score.PassiveErrorRate(),
				})
				if !success {
					if err != nil {
						return err
					}
					return errors.New("http probe failed")
				}
				return nil
			},
		})

		if err := doc.Add(patient); err != nil {
			logger.Fields("domain", domain, "server", srv.Address, "error", err).Warn("failed to add http health patient")
		} else {
			count++
		}
	}
	return count
}
