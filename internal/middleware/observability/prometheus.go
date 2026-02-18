package observability

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/xlib"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agbero_http_requests_total",
			Help: "Total number of HTTP requests made.",
		},
		[]string{"host", "method", "code"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "agbero_http_request_duration_seconds",
			Help:    "HTTP request latency distribution.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"host", "method"},
	)

	lastRequestTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "agbero_last_request_timestamp_seconds",
			Help: "Unix timestamp of the last request served per host.",
		},
		[]string{"host"},
	)

	activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "agbero_active_connections",
			Help: "Number of requests currently in flight.",
		},
		[]string{"host"},
	)

	circuitBreakerTripped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "agbero_circuit_breaker_tripped_total",
			Help: "Total circuit breaker trips per backend",
		},
		[]string{"backend", "host"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(lastRequestTimestamp)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(circuitBreakerTripped)
}

func Prometheus(hm *discovery.Host) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			host := xlib.NormalizeHost(r.Host)

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

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		// If Write is called without WriteHeader, Go assumes 200 OK
		rw.WriteHeader(http.StatusOK)
	}
	// Pass directly to underlying writer. Do not buffer.
	return rw.ResponseWriter.Write(b)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if rf, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(rw.ResponseWriter, r)
}
