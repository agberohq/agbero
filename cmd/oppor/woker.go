// cmd/oppor/worker.go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type Worker struct {
	ID       int
	Config   *Config
	Metrics  *Metrics
	Client   *http.Client
	StopChan chan struct{}
	IPPool   []string
	Counter  *uint64
}

func NewWorker(id int, cfg *Config, metrics *Metrics, counter *uint64) *Worker {
	transport := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !cfg.KeepAlive,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if cfg.RandomIPs {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   cfg.Timeout,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	// Generate IP pool
	var ipPool []string
	if cfg.RandomIPs {
		ipPool = generateIPPool(cfg.IPPoolSize)
	}

	return &Worker{
		ID:       id,
		Config:   cfg,
		Metrics:  metrics,
		Client:   client,
		StopChan: make(chan struct{}),
		IPPool:   ipPool,
		Counter:  counter,
	}
}

func (w *Worker) Run() {
	var limiter *rate.Limiter
	if w.Config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(w.Config.RateLimit), w.Config.RateLimit)
	}

	for {
		select {
		case <-w.StopChan:
			return
		default:
			if limiter != nil {
				limiter.Wait(context.Background())
			}

			// Check if we've reached request limit
			if w.Config.Requests > 0 {
				current := atomic.LoadUint64(w.Counter)
				if current >= uint64(w.Config.Requests) {
					return
				}
				atomic.AddUint64(w.Counter, 1)
			}

			w.makeRequest()
		}
	}
}

func (w *Worker) makeRequest() {
	w.Metrics.ActiveConnections.Add(1)
	defer w.Metrics.ActiveConnections.Add(-1)

	target := w.Config.Targets[rand.Intn(len(w.Config.Targets))]
	start := time.Now()

	var bodyReader io.Reader
	if w.Config.Body != "" && (w.Config.Method == "POST" || w.Config.Method == "PUT") {
		bodyReader = strings.NewReader(w.Config.Body)
	}

	req, err := http.NewRequest(w.Config.Method, target, bodyReader)
	if err != nil {
		w.Metrics.Record(time.Since(start), 0, 0, err)
		// ALWAYS log errors
		logQueue <- fmt.Sprintf("[Worker %d] ERROR creating request: %v", w.ID, err)
		return
	}

	// Add random IP if enabled
	if w.Config.RandomIPs && len(w.IPPool) > 0 {
		ip := w.IPPool[rand.Intn(len(w.IPPool))]
		req.Header.Set("X-Forwarded-For", ip)
		req.Header.Set("X-Real-IP", ip)
	}

	// Add custom headers
	for _, header := range w.Config.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Add body length
	if w.Config.Body != "" && (w.Config.Method == "POST" || w.Config.Method == "PUT") {
		req.ContentLength = int64(len(w.Config.Body))
	}

	resp, err := w.Client.Do(req)
	latency := time.Since(start)

	if err != nil {
		w.Metrics.Record(latency, 0, 0, err)
		// ALWAYS log errors
		logQueue <- fmt.Sprintf("[Worker %d] ERROR: %v", w.ID, err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	var body []byte
	if w.Config.Verbose || w.Config.Follow {
		body, _ = io.ReadAll(resp.Body)
	} else {
		io.Copy(io.Discard, resp.Body)
	}

	w.Metrics.Record(latency, resp.StatusCode, int64(len(body)), nil)

	// Log if verbose OR if status code is an error
	if w.Config.Verbose || resp.StatusCode >= 400 {
		logMsg := fmt.Sprintf("[Worker %d] %s %s - %d (%s) - %v",
			w.ID, w.Config.Method, target, resp.StatusCode, http.StatusText(resp.StatusCode), latency)
		logQueue <- logMsg
	}
}

func generateIPPool(size int) []string {
	pool := make([]string, size)
	for i := 0; i < size; i++ {
		// Generate realistic-looking IPs
		pool[i] = fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(223)+1, // 1-223 (avoid 0.x, 224+)
			rand.Intn(256),
			rand.Intn(256),
			rand.Intn(254)+1) // Avoid .0 and .255
	}
	return pool
}
