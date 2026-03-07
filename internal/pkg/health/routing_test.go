package health

import (
	"testing"
	"time"
)

func TestEffectiveWeightHealthy(t *testing.T) {
	rw := DefaultRoutingWeights()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Healthy at 90
	score.Update(266*time.Millisecond, true, 0, 100)

	weight := rw.EffectiveWeight(100, score)
	expected := int(float64(100) * 0.90)

	if weight != expected {
		t.Errorf("expected weight %d for healthy backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightDegraded(t *testing.T) {
	rw := DefaultRoutingWeights()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Degraded at 75
	score.Update(1129*time.Millisecond, true, 0, 100)

	weight := rw.EffectiveWeight(100, score)
	flo := float64(100) * 0.75 * 0.5
	expected := int(flo)

	if weight != expected {
		t.Errorf("expected weight %d for degraded backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightUnhealthy(t *testing.T) {
	rw := DefaultRoutingWeights()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Unhealthy at 30
	score.Update(2000*time.Millisecond, false, 0, 100)

	weight := rw.EffectiveWeight(100, score)
	expected := int(float64(100) * 0.30 * 0.1)

	if weight != expected {
		t.Errorf("expected weight %d for unhealthy backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightDead(t *testing.T) {
	rw := DefaultRoutingWeights()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Dead at 0
	score.Update(10000*time.Millisecond, false, 1.0, 0)

	weight := rw.EffectiveWeight(100, score)

	if weight != 0 {
		t.Errorf("expected weight 0 for dead backend, got %d", weight)
	}
}

func TestEarlyAbortController(t *testing.T) {
	eac := NewEarlyAbortController(true)

	if !eac.enabled.Load() {
		t.Error("controller should be enabled")
	}

	eac.Disable()
	if eac.enabled.Load() {
		t.Error("Disable should set enabled to false")
	}

	eac.Enable()
	if !eac.enabled.Load() {
		t.Error("Enable should set enabled to true")
	}
}

func TestShouldAbortRapidDeterioration(t *testing.T) {
	eac := NewEarlyAbortController(true)
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Start healthy
	score.Update(50*time.Millisecond, true, 0, 100)

	// Rapid drop
	score.Update(5000*time.Millisecond, false, 0.5, 50)

	shouldAbort := eac.ShouldAbort("backend-1", score)
	if !shouldAbort {
		t.Error("should abort on rapid deterioration")
	}

	select {
	case id := <-eac.AbortChannel():
		if id != "backend-1" {
			t.Errorf("expected backend-1 in abort channel, got %s", id)
		}
	default:
		t.Error("expected abort signal in channel")
	}
}

func TestShouldAbortUnhealthy(t *testing.T) {
	eac := NewEarlyAbortController(true)
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Make unhealthy
	score.Update(2000*time.Millisecond, false, 0, 100)

	if score.State() != StateUnhealthy {
		t.Fatalf("setup failed: expected unhealthy state")
	}

	shouldAbort := eac.ShouldAbort("backend-2", score)
	if !shouldAbort {
		t.Error("should abort when unhealthy")
	}
}

func TestShouldNotAbortWhenDisabled(t *testing.T) {
	eac := NewEarlyAbortController(false)
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(5000*time.Millisecond, false, 0.5, 50)

	shouldAbort := eac.ShouldAbort("backend-3", score)
	if shouldAbort {
		t.Error("should not abort when disabled")
	}
}
