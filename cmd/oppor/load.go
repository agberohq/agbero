package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type Load struct {
	Config   LoadConfig
	Metrics  *LoadMetrics
	counter  atomic.Uint64 // Use atomic.Uint64 for proper atomic operations
	stop     chan bool
	stopOnce sync.Once // Ensure stop channel is closed only once
	wg       sync.WaitGroup
	limiter  *rate.Limiter
	client   *http.Client
	results  chan RequestResult
}

type RequestResult struct {
	Success    bool
	Latency    time.Duration
	Bytes      int64
	StatusCode int
	Error      error
	Timestamp  time.Time
	WorkerID   int
}

func NewLoad(cfg LoadConfig) *Load {
	transport := &http.Transport{
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	lt := &Load{
		Config:  cfg,
		Metrics: NewLoadMetrics(),
		stop:    make(chan bool),
		results: make(chan RequestResult, cfg.Concurrency*10),
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}

	if cfg.RateLimit > 0 {
		lt.limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	}

	return lt
}

func (lt *Load) Run() *LoadMetrics {
	totalReqs := uint64(lt.Config.Requests)
	if totalReqs == 0 {
		totalReqs = math.MaxUint64
	}

	// Start result processor
	go lt.processResults()

	// Start workers
	for i := 0; i < lt.Config.Concurrency; i++ {
		lt.wg.Add(1)
		go lt.worker(i+1, totalReqs)
	}

	// Start metrics collector
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	metricsDone := make(chan bool)
	go func() {
		defer close(metricsDone)
		for {
			select {
			case <-ticker.C:
				lt.Metrics.AddPerSecond()
			case <-lt.stop:
				return
			}
		}
	}()

	// Duration or request limit handler
	if lt.Config.Duration > 0 {
		time.AfterFunc(lt.Config.Duration, func() { lt.Stop() })
	}

	lt.wg.Wait()
	lt.Stop()     // Ensure stop is called to signal metrics collector
	<-metricsDone // Wait for metrics collector to finish

	close(lt.results)
	time.Sleep(100 * time.Millisecond) // Let processor finish

	lt.Metrics.EndTime = time.Now()
	return lt.Metrics
}

func (lt *Load) Stop() {
	lt.stopOnce.Do(func() {
		close(lt.stop)
	})
}

func (lt *Load) worker(id int, maxReqs uint64) {
	defer lt.wg.Done()

	for {
		// Check stop signal first
		select {
		case <-lt.stop:
			return
		default:
		}

		// Atomically increment and check counter BEFORE doing work
		// This ensures proper coordination between workers
		current := lt.counter.Add(1)
		if current > maxReqs {
			// We've exceeded the limit, decrement and exit
			lt.counter.Add(^uint64(0)) // Decrement by 1 (add max uint64 which is -1 in two's complement)
			return
		}

		// Apply rate limiting after we've claimed a request slot
		if lt.limiter != nil {
			if err := lt.limiter.Wait(context.Background()); err != nil {
				continue
			}
		}

		result := lt.executeRequest(id)
		select {
		case lt.results <- result:
		case <-lt.stop:
			return
		}
	}
}

func (lt *Load) executeRequest(workerID int) RequestResult {
	target := lt.Config.Targets[time.Now().UnixNano()%int64(len(lt.Config.Targets))]

	var bodyReader io.Reader
	if lt.Config.Body != "" {
		bodyReader = bytes.NewReader([]byte(lt.Config.Body))
	}

	req, err := http.NewRequest(lt.Config.Method, target, bodyReader)
	if err != nil {
		return RequestResult{Success: false, Error: err, Timestamp: time.Now(), WorkerID: workerID}
	}

	// Add headers
	for k, v := range lt.Config.Headers {
		req.Header.Set(k, v)
	}

	// Trace timing
	var start, dnsStart, connStart, tlsStart, firstByte time.Time
	var dnsDuration, connDuration, ttfb time.Duration

	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:  func(info httptrace.DNSDoneInfo) { dnsDuration = time.Since(dnsStart) },

		ConnectStart: func(network, addr string) { connStart = time.Now() },
		ConnectDone:  func(network, addr string, err error) { connDuration = time.Since(connStart) },

		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(state tls.ConnectionState, err error) { _ = time.Since(tlsStart) },

		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()

	resp, err := lt.client.Do(req)
	latency := time.Since(start)

	if !firstByte.IsZero() {
		ttfb = firstByte.Sub(start)
	}

	if err != nil {
		return RequestResult{
			Success:   false,
			Latency:   latency,
			Error:     err,
			Timestamp: time.Now(),
			WorkerID:  workerID,
		}
	}
	defer resp.Body.Close()

	bytes, _ := io.Copy(io.Discard, resp.Body)
	success := resp.StatusCode < 400

	// Detailed logging for debugging
	if !success {
		logger.Debugf("[worker %d] %s -> %d (latency: %v, ttfb: %v, dns: %v, conn: %v)",
			workerID, target, resp.StatusCode, latency, ttfb, dnsDuration, connDuration)
	}

	return RequestResult{
		Success:    success,
		Latency:    latency,
		Bytes:      bytes,
		StatusCode: resp.StatusCode,
		Timestamp:  time.Now(),
		WorkerID:   workerID,
	}
}

func (lt *Load) processResults() {
	for result := range lt.results {
		lt.Metrics.Record(result.Success, result.Latency, result.Bytes, result.StatusCode)
		if result.Error != nil {
			lt.Metrics.RecordError(classifyError(result.Error))
		}
	}
}

func classifyError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	switch {
	case contains(errStr, "timeout"):
		return "timeout"
	case contains(errStr, "connection refused"):
		return "connection_refused"
	case contains(errStr, "no such host"):
		return "dns_error"
	case contains(errStr, "tls"):
		return "tls_error"
	case contains(errStr, "reset"):
		return "connection_reset"
	default:
		return "other"
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
