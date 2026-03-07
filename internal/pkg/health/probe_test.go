package health

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestProberStandardProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
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

	prober := NewProber(config, server.URL, score, onResult)
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
		if r.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", r.StatusCode)
		}
	}
}

func TestProberFailedProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()

	var result ProbeResult
	onResult := func(r ProbeResult) {
		result = r
	}

	prober := NewProber(config, server.URL, score, onResult)
	prober.executeProbe(ProbeStandard)

	if result.Success {
		t.Error("expected failed probe for 503 response")
	}
	if result.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", result.StatusCode)
	}
}

func TestProberAcceleratedProbing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()
	config.AcceleratedProbing = true
	config.StandardInterval = 10 * time.Second // Don't run standard probes

	prober := NewProber(config, server.URL, score, nil)
	prober.Start()
	defer prober.Stop()

	// Trigger accelerated probing
	prober.TriggerAccelerated()

	time.Sleep(100 * time.Millisecond)

	if !prober.acceleratedActive.Load() {
		t.Error("accelerated probing should be active after trigger")
	}
}

func TestProberSyntheticProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	config := DefaultProbeConfig()
	config.SyntheticWhenIdle = true
	config.SyntheticIdleTimeout = 50 * time.Millisecond
	config.StandardInterval = 10 * time.Second

	prober := NewProber(config, server.URL, score, nil)
	prober.Start()
	defer prober.Stop()

	// Wait for synthetic idle timeout
	time.Sleep(150 * time.Millisecond)

	// Should trigger synthetic probe
	if prober.shouldRunSynthetic() {
		// This verifies the logic, actual probe happens in loop
	} else {
		t.Error("should run synthetic probe after idle timeout")
	}

	// Record activity
	prober.RecordRequestActivity()
	if prober.shouldRunSynthetic() {
		t.Error("should not run synthetic after activity recorded")
	}
}

func TestProberRequestActivity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)
	prober := NewProber(DefaultProbeConfig(), server.URL, score, nil)

	initial := prober.lastRequestTime.Load().(time.Time)
	time.Sleep(10 * time.Millisecond)

	prober.RecordRequestActivity()
	updated := prober.lastRequestTime.Load().(time.Time)

	if !updated.After(initial) {
		t.Error("RecordRequestActivity should update timestamp")
	}
}
