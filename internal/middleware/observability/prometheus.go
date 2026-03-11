package observability

import (
	"net/http"
	"strconv"
	"time"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
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
			host := zulu.NormalizeHost(r.Host)

			if hm.Get(host) == nil {
				host = "unauthorized_or_unknown"
			}

			activeConnections.WithLabelValues(host).Inc()
			defer activeConnections.WithLabelValues(host).Dec()

			rw := &zulu.ResponseWriter{ResponseWriter: w, StatusCode: http.StatusOK}
			next.ServeHTTP(rw, r)

			duration := time.Since(start).Seconds()
			httpRequestsTotal.WithLabelValues(host, r.Method, strconv.Itoa(rw.StatusCode)).Inc()
			httpRequestDuration.WithLabelValues(host, r.Method).Observe(duration)
			lastRequestTimestamp.WithLabelValues(host).Set(float64(time.Now().Unix()))
		})
	}
}
