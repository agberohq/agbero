package health

import "time"

type Multiplier struct {
	DegradedMultiplier  float64
	UnhealthyMultiplier float64
	DrainTimeout        int64 // nanoseconds
	EarlyAbortEnabled   bool
}

func DefaultRoutingMultiplier() Multiplier {
	return Multiplier{
		DegradedMultiplier:  0.5,
		UnhealthyMultiplier: 0.1,
		DrainTimeout:        int64(30 * time.Second),
		EarlyAbortEnabled:   true,
	}
}

func (rw *Multiplier) EffectiveWeight(configuredWeight int, score *Score) int {
	if configuredWeight <= 0 {
		configuredWeight = 1
	}

	state := score.State()
	baseScore := float64(score.Value()) / 100.0

	switch state {
	case StateHealthy:
		return int(float64(configuredWeight) * baseScore)

	case StateDegraded:
		healthWeight := float64(configuredWeight) * baseScore
		return int(healthWeight * rw.DegradedMultiplier)

	case StateUnhealthy:
		healthWeight := float64(configuredWeight) * baseScore
		return int(healthWeight * rw.UnhealthyMultiplier)

	case StateDead:
		return 0
	}

	return 0
}
