package health

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/olekukonko/jack"
)

type ProbeType int

const (
	ProbeStandard ProbeType = iota
	ProbeAccelerated
	ProbeSynthetic
)

type ProbeConfig struct {
	Path                 string
	StandardInterval     time.Duration
	AcceleratedInterval  time.Duration
	SyntheticIdleTimeout time.Duration
	Timeout              time.Duration
	LatencyThresholds    LatencyThresholds
	AcceleratedProbing   bool
	SyntheticWhenIdle    bool
}

func DefaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		Path:                 "/health",
		StandardInterval:     10 * time.Second,
		AcceleratedInterval:  1 * time.Second,
		SyntheticIdleTimeout: 60 * time.Second,
		Timeout:              5 * time.Second,
		LatencyThresholds:    DefaultLatencyThresholds(),
		AcceleratedProbing:   true,
		SyntheticWhenIdle:    true,
	}
}

type ProbeResult struct {
	Type       ProbeType
	Success    bool
	Latency    time.Duration
	Timestamp  time.Time
	StatusCode int
	Error      error
}

type Prober struct {
	config          ProbeConfig
	score           *Score
	executor        Executor
	looper          *jack.Looper
	lastRequestTime atomic.Value
	onResult        func(ProbeResult)
}

func NewProber(config ProbeConfig, executor Executor, score *Score, onResult func(ProbeResult)) *Prober {
	p := &Prober{
		config:   config,
		score:    score,
		executor: executor,
		onResult: onResult,
	}
	p.lastRequestTime.Store(time.Now())

	p.looper = jack.NewLooper(
		func() error { return p.runProbe() },
		jack.WithLooperName("health-prober"),
		jack.WithLooperInterval(config.StandardInterval),
		jack.WithLooperJitter(0.2),
		jack.WithLooperImmediate(true),
	)

	return p
}

func (p *Prober) Start() {
	p.looper.Start()
}

func (p *Prober) Stop() {
	p.looper.Stop()
}

func (p *Prober) RecordRequestActivity() {
	p.lastRequestTime.Store(time.Now())
}

func (p *Prober) runProbe() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()

	start := time.Now()
	success, latency, err := p.executor.Probe(ctx)

	p.recordResult(ProbeResult{
		Type:      ProbeStandard,
		Success:   success,
		Latency:   latency,
		Timestamp: start,
		Error:     err,
	})

	p.adjustInterval()
	return nil
}

func (p *Prober) adjustInterval() {
	if !p.config.AcceleratedProbing {
		return
	}

	state := p.score.State()
	current := p.looper.CurrentInterval()

	shouldAccelerate := state == StateDegraded || state == StateUnhealthy

	if shouldAccelerate && current != p.config.AcceleratedInterval {
		p.looper.SetInterval(p.config.AcceleratedInterval)
	} else if !shouldAccelerate && current != p.config.StandardInterval {
		p.looper.ResetInterval()
	}
}

func (p *Prober) recordResult(result ProbeResult) {
	passiveRate := p.score.PassiveErrorRate()
	connHealth := int32(100)

	p.score.Update(result.Latency, result.Success, passiveRate, connHealth)

	if p.onResult != nil {
		p.onResult(result)
	}
}
