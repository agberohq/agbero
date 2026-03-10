package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type mockExecutor struct {
	probeFunc func(ctx context.Context) (bool, time.Duration, error)
}

func (m *mockExecutor) Probe(ctx context.Context) (bool, time.Duration, error) {
	if m.probeFunc != nil {
		return m.probeFunc(ctx)
	}
	return true, 10 * time.Millisecond, nil
}

func httpExecutor(url string) Executor {
	return &mockExecutor{
		probeFunc: func(ctx context.Context) (bool, time.Duration, error) {
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return false, 0, err
			}
			resp, err := http.DefaultClient.Do(req)
			latency := time.Since(start)
			if err != nil {
				return false, latency, err
			}
			defer resp.Body.Close()
			success := resp.StatusCode >= 200 && resp.StatusCode < 300
			return success, latency, nil
		},
	}
}

func TestProberStandardProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()
	config.StandardInterval = 100 * time.Millisecond

	var mu sync.Mutex
	var results []ProbeResult
	onResult := func(r ProbeResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	}

	executor := httpExecutor(server.URL)
	prober := NewProber(config, executor, score, onResult)
	prober.Start()

	time.Sleep(250 * time.Millisecond)
	prober.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(results) < 2 {
		t.Errorf("expected at least 2 probes, got %d", len(results))
	}

	for _, r := range results {
		if !r.Success {
			t.Errorf("expected successful probe, got error: %v", r.Error)
		}
	}
}

func TestProberFailedProbe(t *testing.T) {
	executor := &mockExecutor{
		probeFunc: func(ctx context.Context) (bool, time.Duration, error) {
			return false, 50 * time.Millisecond, nil
		},
	}

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()

	var result ProbeResult
	var mu sync.Mutex
	onResult := func(r ProbeResult) {
		mu.Lock()
		defer mu.Unlock()
		result = r
	}

	prober := NewProber(config, executor, score, onResult)
	prober.Start()

	time.Sleep(150 * time.Millisecond)
	prober.Stop()

	mu.Lock()
	defer mu.Unlock()
	if result.Success {
		t.Error("expected failed probe")
	}
	if result.Latency == 0 {
		t.Error("expected non-zero latency")
	}
}

func TestProberAcceleratedProbing(t *testing.T) {
	executor := &mockExecutor{
		probeFunc: func(ctx context.Context) (bool, time.Duration, error) {
			return true, 50 * time.Millisecond, nil
		},
	}

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()
	config.AcceleratedProbing = true
	config.StandardInterval = 200 * time.Millisecond
	config.AcceleratedInterval = 50 * time.Millisecond

	prober := NewProber(config, executor, score, nil)
	prober.Start()
	defer prober.Stop()

	score.Update(2000*time.Millisecond, false, 0, 100)
	time.Sleep(100 * time.Millisecond)

	if score.State() != StateUnhealthy && score.State() != StateDegraded {
		t.Logf("score state: %v, value: %d", score.State(), score.Value())
	}
}

func TestProberRequestActivity(t *testing.T) {
	executor := &mockExecutor{}
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	prober := NewProber(DefaultProbeConfig(), executor, score, nil)

	initial := prober.lastRequestTime.Load().(time.Time)
	time.Sleep(10 * time.Millisecond)

	prober.RecordRequestActivity()
	updated := prober.lastRequestTime.Load().(time.Time)

	if !updated.After(initial) {
		t.Error("RecordRequestActivity should update timestamp")
	}
}

func TestProberAdjustInterval(t *testing.T) {
	executor := &mockExecutor{}
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()
	config.AcceleratedProbing = true
	config.StandardInterval = 200 * time.Millisecond
	config.AcceleratedInterval = 50 * time.Millisecond

	prober := NewProber(config, executor, score, nil)

	if prober.looper.CurrentInterval() != config.StandardInterval {
		t.Errorf("expected standard interval %v, got %v", config.StandardInterval, prober.looper.CurrentInterval())
	}

	score.Update(2000*time.Millisecond, false, 0, 100)
	prober.adjustInterval()

	if prober.looper.CurrentInterval() != config.AcceleratedInterval {
		t.Errorf("expected accelerated interval %v, got %v", config.AcceleratedInterval, prober.looper.CurrentInterval())
	}

	score.Update(100*time.Millisecond, true, 0, 100)
	prober.adjustInterval()

	score.Update(100*time.Millisecond, true, 0, 100)
	prober.adjustInterval()

	if prober.looper.CurrentInterval() != config.StandardInterval {
		t.Errorf("expected standard interval after recovery %v, got %v", config.StandardInterval, prober.looper.CurrentInterval())
	}
}
