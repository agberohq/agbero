package health

import "time"

func DefaultScoringWeights() Weights {
	return Weights{
		LatencyWeight: 0.40,
		SuccessWeight: 0.30,
		PassiveWeight: 0.20,
		ConnWeight:    0.10,
	}
}

func DefaultLatencyThresholds() Latency {
	return Latency{
		BaselineMs:     100,
		DegradedFactor: 3.0,
		UnhealthyMs:    1000,
	}
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		HealthyMin:    80,
		DegradedMax:   79,
		UnhealthyMax:  49,
		DeadMax:       9,
		DegradedExit:  85,
		UnhealthyExit: 55,
		DeadExit:      15,
	}
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
