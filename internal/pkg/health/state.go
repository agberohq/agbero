package health

const (
	StateHealthy State = iota
	StateDegraded
	StateUnhealthy
	StateDead
	StateUnknown
)

type State int32

func (s State) String() string {
	return string(s.Status())
}

func (s State) Status() Status {
	switch s {
	case StateHealthy:
		return StatusHealthy
	case StateDegraded:
		return StatusDegraded
	case StateUnhealthy:
		return StatusUnhealthy
	case StateDead:
		return StatusDead
	case StateUnknown:
		fallthrough
	default:
		return StatusUnknown
	}
}

type Status string

const (
	StatusHealthy   = "Healthy"
	StatusDegraded  = "Degraded"
	StatusUnhealthy = "Unhealthy"
	StatusDead      = "Dead"
	StatusUnknown   = "Unknown"
)
