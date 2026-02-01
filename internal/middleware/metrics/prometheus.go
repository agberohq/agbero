package metrics

import (
	"net/http"
	"strconv"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// 1. Total Requests (Counter)
	// Labels: host, method, code
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agbero_http_requests_total",
			Help: "Total number of HTTP requests made.",
		},
		[]string{"host", "method", "code"},
	)

	// 2. Latency (Histogram)
	// Labels: host, method
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "agbero_http_request_duration_seconds",
			Help:    "HTTP request latency distribution.",
			Buckets: prometheus.DefBuckets, // .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
		},
		[]string{"host", "method"},
	)

	// 3. Idle Timer (Gauge)
	// Solves your "how long has it been idle" question.
	lastRequestTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "agbero_last_request_timestamp_seconds",
			Help: "Unix timestamp of the last request served per host.",
		},
		[]string{"host"},
	)

	// 4. Active Connections (Gauge)
	activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "agbero_active_connections",
			Help: "Number of requests currently in flight.",
		},
		[]string{"host"},
	)
)

func init() {
	// Register metrics with Prometheus's default registry
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(lastRequestTimestamp)
	prometheus.MustRegister(activeConnections)
}

// Middleware wraps the handler to capture metrics
func PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Normalize Host for consistent labeling
		host := core.NormalizeHost(r.Host)
		if host == "" {
			host = "unknown"
		}

		activeConnections.WithLabelValues(host).Inc()
		defer activeConnections.WithLabelValues(host).Dec()

		// Wrap ResponseWriter to capture Status Code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		statusCode := strconv.Itoa(rw.statusCode)

		// Record Metrics
		httpRequestsTotal.WithLabelValues(host, r.Method, statusCode).Inc()
		httpRequestDuration.WithLabelValues(host, r.Method).Observe(duration)

		// Update "Last Seen" timestamp for this host
		lastRequestTimestamp.WithLabelValues(host).Set(float64(time.Now().Unix()))
	})
}

// Simple wrapper to steal the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
