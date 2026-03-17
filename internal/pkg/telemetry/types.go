package telemetry

import "time"

// Sample is one point-in-time snapshot captured every CollectInterval.
// Kept intentionally small — only what the UI actually graphs.
type Sample struct {
	Timestamp   int64   `json:"ts"`              // Unix seconds
	RequestsSec float64 `json:"requests_sec"`    // req/s since last sample
	P99Ms       float64 `json:"p99_ms"`          // p99 latency in milliseconds
	ErrorRate   float64 `json:"error_rate"`      // 0.0–100.0 percent
	ActiveBE    int     `json:"active_backends"` // backends currently alive
}

// HostSamples is the set of samples for one host (keyed by domain).
type HostSamples struct {
	Host    string   `json:"host"`
	Samples []Sample `json:"samples"`
}

// QueryRange is parsed from the ?range= query parameter.
type QueryRange struct {
	Duration   time.Duration
	Resolution time.Duration // how we down-sample when returning data
	Label      string
}

var KnownRanges = map[string]QueryRange{
	"30m": {30 * time.Minute, time.Minute, "30 minutes"},
	"1h":  {time.Hour, time.Minute, "1 hour"},
	"6h":  {6 * time.Hour, 5 * time.Minute, "6 hours"},
	"24h": {24 * time.Hour, 15 * time.Minute, "24 hours"},
}

// prevState is held in memory to compute deltas between samples.
type prevState struct {
	totalReqs   uint64
	totalErrors uint64
	capturedAt  time.Time
}
