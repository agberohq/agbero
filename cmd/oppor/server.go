package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Server struct {
	Port       string
	Requests   atomic.Uint64
	Active     atomic.Int64
	Config     ServerConfig
	StartTime  time.Time
	Sessions   sync.Map
	MemoryUsed atomic.Uint64
	Cache      sync.Map
	mu         sync.RWMutex
	latencies  []time.Duration
	server     *http.Server
}

type ServerMetrics struct {
	Port       string    `json:"port"`
	Requests   uint64    `json:"requests"`
	Active     int64     `json:"active_connections"`
	Uptime     float64   `json:"uptime_seconds"`
	MemoryMB   uint64    `json:"memory_used_mb"`
	AvgLatency float64   `json:"avg_latency_ms"`
	P99Latency float64   `json:"p99_latency_ms"`
	ErrorRate  float64   `json:"error_rate"`
	Timestamp  time.Time `json:"timestamp"`
}

func NewServer(port string, cfg ServerConfig) *Server {
	return &Server{
		Port:      port,
		Config:    cfg,
		StartTime: time.Now(),
		latencies: make([]time.Duration, 0, 1000),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handler)
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/metrics", s.metricsHandler)
	mux.HandleFunc("/ready", s.ready)
	mux.HandleFunc("/stats", s.stats)

	// Debug endpoints
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Special endpoints
	if s.Config.SlowEndpoint != "" {
		path := strings.TrimSuffix(s.Config.SlowEndpoint, "*")
		mux.HandleFunc(path, s.slowHandler)
	}

	s.server = &http.Server{
		Addr:         ":" + s.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// TLS setup
	if s.Config.TLSCert != "" && s.Config.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.Config.TLSCert, s.Config.TLSKey)
		if err != nil {
			return fmt.Errorf("failed to load TLS certs: %w", err)
		}
		s.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		fmt.Printf("TLS enabled on port %s\n", s.Port)
	}

	fmt.Printf("Server starting on port %s\n", s.Port)
	go func() {
		var err error
		if s.server.TLSConfig != nil {
			err = s.server.ListenAndServeTLS("", "")
		} else {
			err = s.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error on port %s: %v\n", s.Port, err)
		}
	}()

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s.Requests.Add(1)
	s.Active.Add(1)
	defer s.Active.Add(-1)

	// Record latency
	defer func() {
		s.mu.Lock()
		s.latencies = append(s.latencies, time.Since(start))
		if len(s.latencies) > 10000 {
			s.latencies = s.latencies[len(s.latencies)-5000:]
		}
		s.mu.Unlock()
	}()

	// 1. Failure simulation
	if s.shouldFail() {
		s.sendFailure(w)
		return
	}

	// 2. Session handling
	if s.Config.SessionMode == "sticky" {
		s.handleSession(w, r)
	}

	// 3. Cache simulation
	if s.Config.CacheHitRate > 0 && randFloat() < s.Config.CacheHitRate {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}

	// 4. CPU load simulation
	if s.Config.CPULoad > 0 {
		s.simulateCPU()
	}

	// 5. Memory allocation
	if s.Config.MemoryPerReq > 0 {
		mem := s.allocateMemory(s.Config.MemoryPerReq)
		defer s.freeMemory(mem)
	}

	// 6. Latency simulation
	latency := s.calculateLatency(r.URL.Path)
	if latency > 0 {
		time.Sleep(latency)
	}

	// 7. Generate response
	s.writeResponse(w, r, latency)
}

func (s *Server) shouldFail() bool {
	if s.Config.FailureRate == 0 {
		return false
	}

	switch s.Config.FailurePattern {
	case "periodic":
		return s.Requests.Load()%100 < uint64(s.Config.FailureRate*100)
	case "burst":
		return time.Now().Unix()%60 < int64(s.Config.FailureRate*60)
	default:
		return randFloat() < s.Config.FailureRate
	}
}

func (s *Server) sendFailure(w http.ResponseWriter) {
	codes := s.Config.FailureCodes
	if len(codes) == 0 {
		codes = []int{500, 502, 503, 504}
	}
	code := codes[time.Now().UnixNano()%int64(len(codes))]

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error":     http.StatusText(code),
		"code":      code,
		"server":    s.Port,
		"timestamp": time.Now().Unix(),
	})
}

func (s *Server) calculateLatency(path string) time.Duration {
	if s.Config.SlowEndpoint != "" && strings.HasPrefix(path, strings.TrimSuffix(s.Config.SlowEndpoint, "*")) {
		return 500 * time.Millisecond
	}

	latency := s.Config.BaseLatency

	if s.Config.Jitter > 0 {
		j := time.Duration(randInt63n(int64(s.Config.Jitter)))
		if randFloat() < 0.5 {
			latency += j
		} else {
			latency -= j
		}
	}

	switch s.Config.Speed {
	case "fast":
		latency += time.Millisecond
	case "normal":
		latency += 5 * time.Millisecond
	case "slow":
		latency += 100 * time.Millisecond
	case "erratic":
		latency += time.Duration(randIntn(200)) * time.Millisecond
	}

	if latency < 0 {
		latency = 0
	}
	return latency
}

func (s *Server) simulateCPU() {
	target := time.Duration(float64(time.Millisecond) * s.Config.CPULoad * 10)
	end := time.Now().Add(target)
	for time.Now().Before(end) {
		for i := range 1000 {
			_ = i * i
		}
	}
}

func (s *Server) allocateMemory(mb int) []byte {
	mem := make([]byte, mb*1024*1024)
	for i := range mem {
		mem[i] = byte(i % 256)
	}
	s.MemoryUsed.Add(uint64(mb))
	return mem
}

func (s *Server) freeMemory(mem []byte) {
	s.MemoryUsed.Add(^uint64(len(mem)/(1024*1024) - 1))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("oppor_session")
	if err != nil {
		sessionID := generateSessionID()
		http.SetCookie(w, &http.Cookie{
			Name:     "oppor_session",
			Value:    sessionID,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		})
		s.Sessions.Store(sessionID, time.Now())
		w.Header().Set("X-Session-New", "true")
	} else {
		if _, ok := s.Sessions.Load(cookie.Value); ok {
			w.Header().Set("X-Session-Active", "true")
		}
	}
}

func (s *Server) writeResponse(w http.ResponseWriter, r *http.Request, latency time.Duration) {
	size := s.getResponseSize()
	w.Header().Set("Content-Type", s.getContentType())
	w.Header().Set("X-Server-Port", s.Port)
	w.Header().Set("X-Request-Count", fmt.Sprint(s.Requests.Load()))
	w.Header().Set("X-Response-Latency", latency.String())
	w.Header().Set("X-Server-Time", time.Now().Format(time.RFC3339Nano))

	switch s.Config.ContentMode {
	case "dynamic":
		response := map[string]any{
			"server": map[string]any{
				"port":     s.Port,
				"uptime":   time.Since(s.StartTime).Seconds(),
				"requests": s.Requests.Load(),
				"active":   s.Active.Load(),
			},
			"request": map[string]any{
				"path":    r.URL.Path,
				"method":  r.Method,
				"remote":  r.RemoteAddr,
				"headers": r.Header,
			},
			"performance": map[string]any{
				"latency_ms": latency.Milliseconds(),
				"timestamp":  time.Now().Unix(),
			},
		}
		json.NewEncoder(w).Encode(response)

	case "streaming":
		flusher, ok := w.(http.Flusher)
		if ok {
			w.Header().Set("Transfer-Encoding", "chunked")
			for i := range 10 {
				fmt.Fprintf(w, "chunk %d: %s\n", i, strings.Repeat("x", size/10))
				flusher.Flush()
				time.Sleep(10 * time.Millisecond)
			}
		} else {
			fmt.Fprint(w, strings.Repeat("x", size))
		}

	default:
		fmt.Fprintf(w, "Server: %s\n", s.Port)
		fmt.Fprintf(w, "Requests: %d\n", s.Requests.Load())
		fmt.Fprintf(w, "Active: %d\n", s.Active.Load())
		fmt.Fprintf(w, "Latency: %v\n", latency)
		if size > 0 {
			w.Write([]byte(strings.Repeat("x", size)))
		}
	}
}

func (s *Server) slowHandler(w http.ResponseWriter, r *http.Request) {
	time.Sleep(2 * time.Second)
	s.handler(w, r)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "healthy",
		"port":      s.Port,
		"requests":  s.Requests.Load(),
		"active":    s.Active.Load(),
		"uptime":    time.Since(s.StartTime).Seconds(),
		"memory_mb": s.MemoryUsed.Load(),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if time.Since(s.StartTime) < time.Second {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) metricsHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	latencies := make([]time.Duration, len(s.latencies))
	copy(latencies, s.latencies)
	s.mu.RUnlock()

	var avg, p99 time.Duration
	if len(latencies) > 0 {
		slices.Sort(latencies)
		var sum time.Duration
		for _, l := range latencies {
			sum += l
		}
		avg = sum / time.Duration(len(latencies))
		p99Index := int(float64(len(latencies)) * 0.99)
		if p99Index >= len(latencies) {
			p99Index = len(latencies) - 1
		}
		p99 = latencies[p99Index]
	}

	metrics := ServerMetrics{
		Port:       s.Port,
		Requests:   s.Requests.Load(),
		Active:     s.Active.Load(),
		Uptime:     time.Since(s.StartTime).Seconds(),
		MemoryMB:   s.MemoryUsed.Load(),
		AvgLatency: float64(avg.Milliseconds()),
		P99Latency: float64(p99.Milliseconds()),
		Timestamp:  time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"server": map[string]any{
			"port":     s.Port,
			"requests": s.Requests.Load(),
			"active":   s.Active.Load(),
			"uptime":   time.Since(s.StartTime).Seconds(),
		},
		"memory": map[string]any{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"gc_runs":     m.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
	})
}

func (s *Server) getContentType() string {
	switch s.Config.ContentMode {
	case "dynamic":
		return "application/json"
	case "streaming":
		return "text/plain; charset=utf-8"
	default:
		return "text/plain"
	}
}

func (s *Server) getResponseSize() int {
	switch s.Config.ResponseSize {
	case "1KB":
		return 1024
	case "10KB":
		return 10 * 1024
	case "100KB":
		return 100 * 1024
	case "1MB":
		return 1024 * 1024
	case "10MB":
		return 10 * 1024 * 1024
	default:
		return 0
	}
}

func runServer(cfg ServerConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	var ports []string
	if cfg.Port != "" {
		ports = []string{cfg.Port}
	} else if cfg.PortRange != "" {
		parts := strings.Split(cfg.PortRange, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for p := start; p <= end; p++ {
				ports = append(ports, strconv.Itoa(p))
			}
		}
	}

	if len(ports) == 0 {
		ports = []string{"8080"}
	}

	// Set defaults based on speed
	if cfg.Speed != "" && cfg.BaseLatency == 0 {
		switch cfg.Speed {
		case "fast":
			cfg.BaseLatency = time.Millisecond
		case "normal":
			cfg.BaseLatency = 10 * time.Millisecond
		case "slow":
			cfg.BaseLatency = 100 * time.Millisecond
		case "erratic":
			cfg.BaseLatency = 50 * time.Millisecond
			cfg.Jitter = 100 * time.Millisecond
		}
	}

	servers := make([]*Server, 0, len(ports))
	fmt.Printf("\nStarting %d servers:\n", len(ports))

	for _, port := range ports {
		s := NewServer(port, cfg)
		if err := s.Start(); err != nil {
			return fmt.Errorf("failed to start server on port %s: %w", port, err)
		}
		servers = append(servers, s)
	}

	fmt.Println("\nPress Ctrl+C to stop")

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, s := range servers {
		if err := s.Stop(ctx); err != nil {
			fmt.Printf("Error stopping server %s: %v\n", s.Port, err)
		}
	}

	return nil
}

// Helper functions for deterministic testing
func randFloat() float64 {
	return float64(time.Now().UnixNano()%10000) / 10000
}

func randInt63n(n int64) int64 {
	return time.Now().UnixNano() % n
}

func randIntn(n int) int {
	return int(time.Now().UnixNano() % int64(n))
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
