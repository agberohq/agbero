package xhttp

import (
	"context"
	"net/http"
	"net/url"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/health"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

func RegisterHTTPPatients(domain string, route *alaye.Route, doc *jack.Doctor, registry *metrics.Registry, logger *ll.Logger) {
	if route.Backends.Enabled.NotActive() || len(route.Backends.Servers) == 0 {
		return
	}

	hasProber := false
	if route.HealthCheck.Enabled.Active() {
		hasProber = true
	} else if route.HealthCheck.Enabled == alaye.Unknown && route.HealthCheck.Path != "" {
		hasProber = true
	}

	if !hasProber {
		return
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

	for _, srv := range route.Backends.Servers {
		statsKey := route.BackendKey(domain, srv.Address)
		score := health.GlobalRegistry.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

		u, err := url.Parse(srv.Address)
		if err != nil {
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

		execClient := &http.Client{
			Timeout: probeCfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
				DisableKeepAlives:   true,
			},
		}

		executor := &HTTPExecutor{
			URL:            targetURL,
			Method:         route.HealthCheck.Method,
			Client:         execClient,
			Header:         headers,
			Host:           hostHeader,
			ExpectedStatus: route.HealthCheck.ExpectedStatus,
			ExpectedBody:   route.HealthCheck.ExpectedBody,
		}

		patient := jack.NewPatient(jack.PatientConfig{
			ID:       statsKey,
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
		_ = doc.Add(patient)
	}
}
