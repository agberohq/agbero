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

	if s.State() != StateUnknown {
		t.Errorf("expected initial state Unknown, got %v", s.State())
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

	// Original test cases from your file
	testCases := []struct {
		name          string
		record        Record
		expectedState State
	}{
		{"healthy probe", Record{ProbeLatency: 50 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100}, StateHealthy},
		{"degraded latency", Record{ProbeLatency: 700 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0.5, ConnHealth: 100}, StateDegraded},
		{"unhealthy latency", Record{ProbeLatency: 2000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0, ConnHealth: 100}, StateUnhealthy},
		{"failed probe", Record{ProbeLatency: 2000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0, ConnHealth: 100}, StateUnhealthy},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s.Update(tc.record)

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

	// Enter degraded at <=79
	s.Update(Record{ProbeLatency: 800 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0.5, ConnHealth: 100})
	if s.State() != StateDegraded {
		t.Fatalf("should enter degraded at score <=79, got score=%d, state=%v", s.Value(), s.State())
	}

	// Stay degraded until >=85
	s.Update(Record{ProbeLatency: 250 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0.5, ConnHealth: 100})
	if s.State() != StateDegraded {
		t.Errorf("should stay degraded until score >=85, got score=%d, state=%v", s.Value(), s.State())
	}

	// Exit to healthy
	s.Update(Record{ProbeLatency: 100 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})
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

	s.Update(Record{ProbeLatency: 50 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})
	if s.IsRapidDeterioration() {
		t.Error("should not be deteriorating initially")
	}

	s.Update(Record{ProbeLatency: 5000 * time.Millisecond, ProbeSuccess: false, StatusCode: 500, PassiveRate: 0.5, ConnHealth: 50})

	if !s.IsRapidDeterioration() {
		t.Errorf("should detect rapid deterioration, score=%d, trend=%d", s.Value(), s.Trend())
	}
}

func TestScoreSnapshot(t *testing.T) {
	s := NewScore(DefaultThresholds(), DefaultScoringWeights(), DefaultLatencyThresholds(), nil)

	s.Update(Record{ProbeLatency: 100 * time.Millisecond, ProbeSuccess: true, StatusCode: 200, PassiveRate: 0, ConnHealth: 100})

	snap := s.Snapshot()
	if snap.value != s.Value() {
		t.Error("snapshot value mismatch")
	}
	if snap.state != s.State() {
		t.Error("snapshot state mismatch")
	}
}
