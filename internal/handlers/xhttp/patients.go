package xhttp

import (
	"context"
	"net/http"
	"net/url"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// RegisterHTTPPatients creates a Patient for each backend server in the route..
func RegisterHTTPPatients(res *resource.Manager, doc *jack.Doctor, logger *ll.Logger, route *alaye.Route, domain string) int {
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
		score := res.Health.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

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
			Client:         res.HTTPClient,
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
