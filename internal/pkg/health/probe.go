package health

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type ProbeType int

const (
	ProbeStandard ProbeType = iota
	ProbeAccelerated
	ProbeSynthetic
	ProbeDeep
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
	ProbeBufferSize      int
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
		ProbeBufferSize:      100,
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
	config    ProbeConfig
	client    *http.Client
	targetURL string
	score     *Score

	lastProbeTime   atomic.Value // stores time.Time
	lastRequestTime atomic.Value // stores time.Time

	probeCh chan ProbeType
	stopCh  chan struct{}
	wg      sync.WaitGroup

	onResult func(ProbeResult)

	acceleratedActive atomic.Bool
}

func NewProber(config ProbeConfig, targetURL string, score *Score, onResult func(ProbeResult)) *Prober {
	if config.ProbeBufferSize <= 0 {
		config.ProbeBufferSize = 100
	}

	p := &Prober{
		config:    config,
		targetURL: targetURL,
		score:     score,
		probeCh:   make(chan ProbeType, config.ProbeBufferSize),
		stopCh:    make(chan struct{}),
		onResult:  onResult,
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 2,
				DisableKeepAlives:   false,
			},
		},
	}
	p.lastProbeTime.Store(time.Time{})
	p.lastRequestTime.Store(time.Time{})
	return p
}

func (p *Prober) Start() {
	p.lastRequestTime.Store(time.Now())
	p.wg.Add(1)
	go p.loop()
}

func (p *Prober) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

func (p *Prober) RecordRequestActivity() {
	p.lastRequestTime.Store(time.Now())
}

func (p *Prober) TriggerAccelerated() {
	select {
	case p.probeCh <- ProbeAccelerated:
	default:
		// Channel full, drop probe request
	}
}

func (p *Prober) loop() {
	defer p.wg.Done()

	standardTicker := time.NewTicker(p.config.StandardInterval)
	defer standardTicker.Stop()

	syntheticTicker := time.NewTicker(p.config.SyntheticIdleTimeout / 2)
	defer syntheticTicker.Stop()

	var acceleratedTicker *time.Ticker
	var acceleratedC <-chan time.Time

	if p.config.AcceleratedProbing {
		acceleratedTicker = time.NewTicker(p.config.AcceleratedInterval)
		acceleratedTicker.Stop()
		acceleratedC = acceleratedTicker.C
	}

	for {
		select {
		case <-p.stopCh:
			return

		case <-standardTicker.C:
			p.executeProbe(ProbeStandard)

		case probeType := <-p.probeCh:
			if probeType == ProbeAccelerated && acceleratedTicker != nil && !p.acceleratedActive.Load() {
				p.acceleratedActive.Store(true)
				acceleratedTicker.Reset(p.config.AcceleratedInterval)
			}
			p.executeProbe(probeType)

		case <-acceleratedC:
			state := p.score.State()
			if state == StateDegraded || state == StateUnhealthy {
				p.executeProbe(ProbeAccelerated)
			} else {
				acceleratedTicker.Stop()
				p.acceleratedActive.Store(false)
			}

		case <-syntheticTicker.C:
			if p.shouldRunSynthetic() {
				p.executeProbe(ProbeSynthetic)
			}
		}
	}
}

func (p *Prober) shouldRunSynthetic() bool {
	if !p.config.SyntheticWhenIdle {
		return false
	}
	lastReq := p.lastRequestTime.Load().(time.Time)
	return time.Since(lastReq) > p.config.SyntheticIdleTimeout
}

func (p *Prober) executeProbe(probeType ProbeType) {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
	defer cancel()

	start := time.Now()

	req, err := http.NewRequest(http.MethodGet, p.targetURL+p.config.Path, nil)
	if err != nil {
		p.recordResult(ProbeResult{
			Type:      probeType,
			Success:   false,
			Latency:   time.Since(start),
			Timestamp: start,
			Error:     err,
		})
		return
	}

	req = req.WithContext(ctx)

	resp, err := p.client.Do(req)
	latency := time.Since(start)

	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
		resp.Body.Close()
	}

	success := err == nil && statusCode >= 200 && statusCode < 300

	p.recordResult(ProbeResult{
		Type:       probeType,
		Success:    success,
		Latency:    latency,
		Timestamp:  start,
		StatusCode: statusCode,
		Error:      err,
	})
}

func (p *Prober) recordResult(result ProbeResult) {
	p.lastProbeTime.Store(result.Timestamp)

	passiveRate := p.score.PassiveErrorRate()
	connHealth := int32(100)

	p.score.Update(result.Latency, result.Success, passiveRate, connHealth)

	if p.onResult != nil {
		p.onResult(result)
	}

	if result.Success && p.score.State() == StateDegraded && p.config.AcceleratedProbing {
		p.TriggerAccelerated()
	}
}
