// score_test.go
package health

import (
	"testing"
	"time"
)

func TestNewScore(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	if s.Value() != 100 {
		t.Errorf("expected initial score 100, got %d", s.Value())
	}

	if s.State() != StateHealthy {
		t.Errorf("expected initial state Healthy, got %v", s.State())
	}
}

func TestScoreStateTransitions(t *testing.T) {
	thresholds := DefaultThresholds()
	stateChanges := []struct {
		from State
		to   State
	}{}

	onChange := func(oldState, newState State, score int32) {
		stateChanges = append(stateChanges, struct {
			from State
			to   State
		}{oldState, newState})
	}

	s := NewScore(thresholds, DefaultScoringWeights(), DefaultLatencyThresholds(), onChange)

	// Score formula: latency*0.4 + success*0.3 + passive*0.2 + conn*0.1
	// For failed probe: success=0, so max possible is 0*0.3 + 100*0.2 + 100*0.1 = 30
	// Plus latency component. To get unhealthy (<=49), need latencyScore*0.4 + 30 <= 49
	// latencyScore <= 47.5, which requires >= ~825ms
	testCases := []struct {
		name          string
		probeSuccess  bool
		probeLatency  time.Duration
		passiveRate   float64
		connHealth    int32
		expectedState State
	}{
		{"healthy probe", true, 50 * time.Millisecond, 0, 100, StateHealthy},
		// Degraded: need score 50-79. With success=100, passive=0, conn=100:
		// score = lat*0.4 + 30 + 20 + 10 = lat*0.4 + 60. For 50: lat= -25 (impossible).
		// So with full passive/conn health, we can't hit degraded with success=true.
		// Need passive errors or conn issues. Use passiveRate=0.5 (passiveScore=50)
		// score = lat*0.4 + 30 + 10 + 10 = lat*0.4 + 50. For 70: lat=50, need ~600ms
		{"degraded latency", true, 700 * time.Millisecond, 0.5, 100, StateDegraded},
		// Unhealthy: need <=49. With failure (success=0), passive=0, conn=100:
		// score = lat*0.4 + 0 + 20 + 10 = lat*0.4 + 30. For 49: lat=47.5, need ~850ms
		{"unhealthy latency", false, 1000 * time.Millisecond, 0, 100, StateUnhealthy},
		// Failed probe with high latency: success=0, score = lat*0.4 + 0 + 20 + 10
		// For 1000ms: latScore=40, score = 16 + 30 = 46 (unhealthy)
		{"failed probe", false, 1000 * time.Millisecond, 0, 100, StateUnhealthy},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s.Update(tc.probeLatency, tc.probeSuccess, tc.passiveRate, tc.connHealth)

			if s.State() != tc.expectedState {
				t.Errorf("expected state %v, got %v (score=%d)", tc.expectedState, s.State(), s.Value())
			}
		})
	}

	if len(stateChanges) == 0 {
		t.Error("expected state change callbacks")
	}
}

func TestHysteresis(t *testing.T) {
	thresholds := DefaultThresholds()
	s := NewScore(thresholds, DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Enter degraded at <=79.
	// With success=true, passive=0.5 (score=50), conn=100:
	// total = lat*0.4 + 30 + 10 + 10 = lat*0.4 + 50
	// For 70: latScore=50, need ~700ms latency
	s.Update(800*time.Millisecond, true, 0.5, 100)
	if s.State() != StateDegraded {
		t.Fatalf("should enter degraded at score <=79, got score=%d, state=%v", s.Value(), s.State())
	}

	// Stay degraded until >=85. Current score ~70.
	// To get to 84 (stay degraded): need lat*0.4 + 50 = 84, latScore=85, need ~250ms
	// To get to 86 (exit to healthy): need lat*0.4 + 50 = 86, latScore=90, need ~150ms
	s.Update(250*time.Millisecond, true, 0.5, 100)
	if s.State() != StateDegraded {
		t.Errorf("should stay degraded until score >=85, got score=%d, state=%v", s.Value(), s.State())
	}

	// Now recover to healthy
	s.Update(100*time.Millisecond, true, 0, 100)
	if s.State() != StateHealthy {
		t.Errorf("should exit to healthy at score >=85, got score=%d, state=%v", s.Value(), s.State())
	}
}

func TestCalculateLatencyScore(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	testCases := []struct {
		latency  time.Duration
		expected int32
	}{
		{0, 100},
		{50 * time.Millisecond, 100},
		{100 * time.Millisecond, 100},
		{200 * time.Millisecond, 85},
		{300 * time.Millisecond, 70},
		{500 * time.Millisecond, 61},
		{1000 * time.Millisecond, 40},
		{2000 * time.Millisecond, 24},
	}

	for _, tc := range testCases {
		score := s.calculateLatencyScore(tc.latency)
		if score < tc.expected-5 || score > tc.expected+5 {
			t.Errorf("latency %v: expected score ~%d, got %d", tc.latency, tc.expected, score)
		}
	}
}

func TestPassiveErrorRate(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Record 10 requests, 2 failures
	for i := 0; i < 8; i++ {
		s.RecordPassiveRequest(true)
	}
	for i := 0; i < 2; i++ {
		s.RecordPassiveRequest(false)
	}

	rate := s.PassiveErrorRate()
	if rate != 0.2 {
		t.Errorf("expected error rate 0.2, got %f", rate)
	}
}

func TestRapidDeterioration(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	// Start healthy
	s.Update(50*time.Millisecond, true, 0, 100)
	if s.IsRapidDeterioration() {
		t.Error("should not be deteriorating initially")
	}

	// Rapid drop - use failure + high latency + passive errors to drop score quickly
	s.Update(5000*time.Millisecond, false, 0.5, 50)

	if !s.IsRapidDeterioration() {
		t.Errorf("should detect rapid deterioration, score=%d, trend=%d", s.Value(), s.Trend())
	}
}

func TestScoreSnapshot(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	s.Update(100*time.Millisecond, true, 0, 100)

	snap := s.Snapshot()
	if snap.value != s.Value() {
		t.Error("snapshot value mismatch")
	}
	if snap.state != s.State() {
		t.Error("snapshot state mismatch")
	}
}
