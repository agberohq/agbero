package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cespare/xxhash/v2"
)

type TestServer struct {
	Port         string
	Server       *http.Server
	Started      bool
	StartTime    time.Time
	RequestCount atomic.Uint64
	ServerID     string
}

func NewTestServer(port string) *TestServer {
	mux := http.NewServeMux()

	// Generate server ID from port using xxhash
	hash := xxhash.Sum64([]byte(port))
	serverID := fmt.Sprintf("server-%x", hash)[:10] // First 8 chars of hex

	startTime := time.Now()
	var requestCount uint64

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&requestCount, 1)

		fmt.Fprintf(w, "Test Server %s running on port %s\n", serverID, port)
		fmt.Fprintf(w, "Server ID: %s\n", serverID)
		fmt.Fprintf(w, "Request Path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Query Parameters: %v\n", r.URL.Query())
		fmt.Fprintf(w, "Remote Address: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "Headers:\n")

		// Collect and sort header keys
		headerKeys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			headerKeys = append(headerKeys, k)
		}

		sort.Strings(headerKeys)

		// Print headers in alphabetical order
		for _, k := range headerKeys {
			fmt.Fprintf(w, "  %s: %v\n", k, r.Header[k])
		}

		fmt.Fprintf(w, "\nServer Uptime: %v\n", time.Since(startTime))
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "healthy",
			"id":       serverID,
			"port":     port,
			"uptime":   time.Since(startTime).String(),
			"requests": atomic.LoadUint64(&requestCount),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server": map[string]interface{}{
				"id":       serverID,
				"port":     port,
				"uptime":   time.Since(startTime).Seconds(),
				"requests": atomic.LoadUint64(&requestCount),
				"status":   "running",
			},
		})
	})

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Simulate some processing time
		delay := rand.Intn(100)
		time.Sleep(time.Duration(delay) * time.Millisecond)

		response := map[string]interface{}{
			"status":    "success",
			"server_id": serverID,
			"port":      port,
			"endpoint":  r.URL.Path,
			"method":    r.Method,
			"delay_ms":  delay,
			"timestamp": time.Now().Unix(),
		}

		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			response["body_size"] = len(body)
		}

		json.NewEncoder(w).Encode(response)
	})

	return &TestServer{
		Port:     port,
		ServerID: serverID,
		Server: &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		},
		StartTime: startTime,
	}
}

func (s *TestServer) Start() error {
	go func() {
		fmt.Printf("Starting test server on port %s...\n", s.Port)
		if err := s.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("Server on port %s failed: %v\n", s.Port, err)
		}
	}()

	// Verify server started
	for i := 0; i < 5; i++ {
		time.Sleep(time.Duration(i*100) * time.Millisecond)
		resp, err := http.Get("http://localhost:" + s.Port + "/health")
		if err == nil {
			resp.Body.Close()
			s.Started = true
			return nil
		}
	}
	return fmt.Errorf("server on port %s failed to start", s.Port)
}

func (s *TestServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Server.Shutdown(ctx)
}

func parsePortsForServer(cfg *Config) []string {
	var ports []string

	// Method 1: Comma-separated list (has priority if specified)
	if cfg.PortString != "" {
		for _, p := range strings.Split(cfg.PortString, ",") {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				if portNum, err := strconv.Atoi(trimmed); err == nil {
					if portNum >= 1 && portNum <= 65535 {
						ports = append(ports, trimmed)
					} else {
						logger.Printf("Warning: Port %d out of range (1-65535), skipping", portNum)
					}
				} else {
					logger.Printf("Warning: Invalid port '%s', skipping", trimmed)
				}
			}
		}
		return ports
	}

	// Method 2: Start and end port range
	if cfg.StartPort > 0 && cfg.EndPort > 0 {
		if cfg.StartPort > cfg.EndPort {
			logger.Fatal("Start port must be less than or equal to end port")
		}
		if cfg.StartPort < 1 || cfg.EndPort > 65535 {
			logger.Fatal("Ports must be in range 1-65535")
		}
		for port := cfg.StartPort; port <= cfg.EndPort; port++ {
			ports = append(ports, strconv.Itoa(port))
		}
		return ports
	}

	// Method 3: Start port and total ports
	if cfg.StartPort > 0 && cfg.TotalPorts > 0 {
		if cfg.StartPort < 1 {
			logger.Fatal("Start port must be >= 1")
		}
		if cfg.TotalPorts <= 0 {
			logger.Fatal("Total ports must be > 0")
		}
		endPort := cfg.StartPort + cfg.TotalPorts - 1
		if endPort > 65535 {
			logger.Fatal("Port range exceeds maximum port 65535")
		}
		for i := 0; i < cfg.TotalPorts; i++ {
			ports = append(ports, strconv.Itoa(cfg.StartPort+i))
		}
		return ports
	}

	// If only startPort is given (default to single port)
	if cfg.StartPort > 0 {
		if cfg.StartPort < 1 || cfg.StartPort > 65535 {
			logger.Fatal("Port must be in range 1-65535")
		}
		ports = append(ports, strconv.Itoa(cfg.StartPort))
		return ports
	}

	return ports
}

func runServerMode(cfg *Config) {
	ports := parsePortsForServer(cfg)

	if len(ports) == 0 {
		fmt.Println("\nUsage examples:")
		fmt.Println("  Single port:          ./oppor serve -p 8080")
		fmt.Println("  Multiple ports:       ./oppor serve -p 8080,8081,8082")
		fmt.Println("  Port range:           ./oppor serve -s 8080 -e 8090")
		fmt.Println("  Count from start:     ./oppor serve -s 8080 -t 5")
		fmt.Println("\nNote: -p flag takes precedence over -s/-e/-t flags")
		logger.Fatal("\nNo valid ports specified.")
	}

	fmt.Printf("\nStarting %d test servers on ports: %v\n\n", len(ports), ports)

	servers := make(map[string]*TestServer)
	var wg sync.WaitGroup

	// Start all servers
	for _, port := range ports {
		server := NewTestServer(port)
		servers[port] = server
		wg.Add(1)

		go func(s *TestServer) {
			defer wg.Done()
			if err := s.Start(); err != nil {
				logger.Printf("✗ Failed to start server on port %s: %v", s.Port, err)
			} else {
				fmt.Printf("✓ Test server started on port %s\n", s.Port)
				fmt.Printf("  Health check: http://localhost:%s/health\n", s.Port)
				fmt.Printf("  Metrics:      http://localhost:%s/metrics\n", s.Port)
				fmt.Printf("  API example:  http://localhost:%s/api/test\n", s.Port)
				fmt.Println()
			}
		}(server)
	}

	wg.Wait()

	// Print summary
	fmt.Println("┌────────────────────────────────────────┐")
	fmt.Println("│        Test Servers Running            │")
	fmt.Println("└────────────────────────────────────────┘")
	for port, server := range servers {
		if server.Started {
			fmt.Printf("  Port %s: http://localhost:%s\n", port, port)
		}
	}
	fmt.Println("\nPress Ctrl+C to stop all servers...")

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-sigChan
	fmt.Println("\nShutting down servers...")

	// Stop all servers
	var stopWg sync.WaitGroup
	for _, server := range servers {
		if server.Started {
			stopWg.Add(1)
			go func(s *TestServer) {
				defer stopWg.Done()
				if err := s.Stop(); err != nil {
					logger.Printf("Error stopping server on port %s: %v", s.Port, err)
				} else {
					fmt.Printf("✓ Stopped server on port %s\n", s.Port)
				}
			}(server)
		}
	}

	stopWg.Wait()
	fmt.Println("\nAll servers stopped.")
}
