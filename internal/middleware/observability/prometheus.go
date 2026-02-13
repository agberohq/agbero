package observability

import (
	"net/http"
	"strconv"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
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

func Prometheus(hm *discovery.Host) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			host := core.NormalizeHost(r.Host)

			// Prevent cardinality explosion by verifying the host exists in config
			if hm.Get(host) == nil {
				host = "unauthorized_or_unknown"
			}

			activeConnections.WithLabelValues(host).Inc()
			defer activeConnections.WithLabelValues(host).Dec()

			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)

			duration := time.Since(start).Seconds()
			statusCode := strconv.Itoa(rw.statusCode)

			httpRequestsTotal.WithLabelValues(host, r.Method, statusCode).Inc()
			httpRequestDuration.WithLabelValues(host, r.Method).Observe(duration)
			lastRequestTimestamp.WithLabelValues(host).Set(float64(time.Now().Unix()))
		})
	}
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
