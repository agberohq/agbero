package alaye

// Telemetry configures the built-in time-series performance collector.
//
// When enabled, the proxy samples key metrics every 60 seconds and retains
// up to 24 hours of history. The history is accessible via the protected
// admin endpoint GET /telemetry/history?host=<domain>&range=<30m|1h|6h|24h>.
type Telemetry struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
}
