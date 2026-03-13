package xtcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

func RegisterTCPPatients(listen string, cfg alaye.TCPRoute, doc *jack.Doctor, logger *ll.Logger) int {
	if len(cfg.Backends) == 0 {
		return 0
	}

	probeCfg := health.DefaultProbeConfig()
	if cfg.HealthCheck.Interval > 0 {
		probeCfg.StandardInterval = cfg.HealthCheck.Interval
	}
	if cfg.HealthCheck.Timeout > 0 {
		probeCfg.Timeout = cfg.HealthCheck.Timeout
	}

	send := cfg.HealthCheck.Send
	expect := cfg.HealthCheck.Expect

	var sendBytes, expectBytes []byte
	if send != "" {
		send = strings.ReplaceAll(send, "\\r", "\r")
		send = strings.ReplaceAll(send, "\\n", "\n")
		sendBytes = []byte(send)
	}
	if expect != "" {
		expectBytes = []byte(expect)
	}

	count := 0
	for _, b := range cfg.Backends {
		statsKey := cfg.BackendKey(b.Address)
		score := health.GlobalRegistry.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

		pool := newConnPool(b.Address, 3, probeCfg.Timeout)
		executor := &TCPExecutor{
			Pool:   pool,
			Send:   sendBytes,
			Expect: expectBytes,
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
					return fmt.Errorf("tcp probe failed")
				}
				return nil
			},
			OnRemove: func() {
				pool.close()
			},
		})
		if err := doc.Add(patient); err != nil {
			logger.Fields("listen", listen, "backend", b.Address, "error", err).Warnf("failed to add tcp health patient")
		} else {
			count++
		}
	}
	return count
}
