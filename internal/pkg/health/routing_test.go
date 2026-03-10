// routing_test.go
package health

import (
	"testing"
	"time"
)

func TestEffectiveWeightHealthy(t *testing.T) {
	rw := DefaultRoutingMultiplier()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(Record{ProbeLatency: 266 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})

	weight := rw.EffectiveWeight(100, score)
	expected := int(float64(100) * 0.90)

	if weight != expected {
		t.Errorf("expected weight %d for healthy backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightDegraded(t *testing.T) {
	rw := DefaultRoutingMultiplier()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(Record{ProbeLatency: 1129 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})

	weight := rw.EffectiveWeight(100, score)
	expected := int(float64(100) * float64(score.Value()) / 100.0 * rw.DegradedMultiplier)

	if weight != expected {
		t.Errorf("expected weight %d for degraded backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightUnhealthy(t *testing.T) {
	rw := DefaultRoutingMultiplier()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(Record{ProbeLatency: 2000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0, ConnHealth: 100})

	weight := rw.EffectiveWeight(100, score)
	expected := int(float64(100) * float64(score.Value()) / 100.0 * rw.UnhealthyMultiplier)

	if weight != expected {
		t.Errorf("expected weight %d for unhealthy backend, got %d", expected, weight)
	}
}

func TestEffectiveWeightDead(t *testing.T) {
	rw := DefaultRoutingMultiplier()
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(Record{ProbeLatency: 10000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 1.0, ConnHealth: 0})

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

	score.Update(Record{ProbeLatency: 50 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})

	score.Update(Record{ProbeLatency: 5000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0.5, ConnHealth: 50})

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

	score.Update(Record{ProbeLatency: 2000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0, ConnHealth: 100})

	if score.State() != StateUnhealthy {
		t.Fatalf("setup failed: expected unhealthy state, got %v", score.State())
	}

	shouldAbort := eac.ShouldAbort("backend-2", score)
	if !shouldAbort {
		t.Error("should abort when unhealthy")
	}
}

func TestShouldNotAbortWhenDisabled(t *testing.T) {
	eac := NewEarlyAbortController(false)
	score := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	score.Update(Record{ProbeLatency: 5000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0.5, ConnHealth: 50})

	shouldAbort := eac.ShouldAbort("backend-3", score)
	if shouldAbort {
		t.Error("should not abort when disabled")
	}
}
