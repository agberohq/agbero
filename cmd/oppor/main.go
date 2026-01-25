package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/integrii/flaggy"
	"github.com/olekukonko/ll"
)

var (
	logger = ll.New("opopo", ll.WithFatalExits(true))
)

var logQueue = make(chan string, 1000)

var (
	// CLI flags
	targets     []string
	concurrency int
	requests    int
	duration    string
	rateLimit   int
	method      string
	headers     []string
	body        string
	keepAlive   bool
	timeout     string
	randomIPs   bool
	ipPoolSize  int
	outputJSON  bool
	verbose     bool
	follow      bool
	metricsURL  string
	showLatency bool

	// Server flags
	serveMode  bool
	portString string
	startPort  int
	endPort    int
	totalPorts int

	// Global state
	startTime    time.Time
	requestCount uint64
)

func main() {
	flaggy.SetName("oppor")
	flaggy.SetDescription("Open Performance & Proxy Observer - Test server and load testing tool")
	flaggy.SetVersion("1.0.0")

	// Create the serve subcommand
	serveCmd := flaggy.NewSubcommand("serve")
	serveCmd.Description = "Run in server mode (create test servers)"
	serveCmd.String(&portString, "p", "port", "Comma-separated ports (e.g., 8080,8081,8082)")
	serveCmd.Int(&startPort, "s", "start", "Start port number")
	serveCmd.Int(&endPort, "e", "end", "End port number (for range)")
	serveCmd.Int(&totalPorts, "P", "total", "Number of ports from start")

	// Add the serve subcommand to flaggy
	flaggy.AttachSubcommand(serveCmd, 1)

	// Load test flags (main command flags)
	flaggy.StringSlice(&targets, "t", "target", "Target URLs (comma-separated or repeated)")
	flaggy.Int(&concurrency, "c", "concurrency", "Number of concurrent workers (default: 10)")
	flaggy.Int(&requests, "n", "requests", "Total number of requests (0 = infinite)")
	flaggy.String(&duration, "d", "duration", "Test duration (e.g., 30s, 5m, 1h)")
	flaggy.Int(&rateLimit, "r", "rate", "Requests per second per worker (0 = unlimited)")
	flaggy.String(&method, "X", "method", "HTTP method (default: GET)")
	flaggy.StringSlice(&headers, "H", "header", "HTTP headers (key:value)")
	flaggy.String(&body, "b", "body", "Request body")
	flaggy.Bool(&keepAlive, "k", "keepalive", "Use HTTP keep-alive")
	flaggy.String(&timeout, "T", "timeout", "Request timeout (default: 30s)")
	flaggy.Bool(&randomIPs, "i", "random-ips", "Use random source IPs")
	flaggy.Int(&ipPoolSize, "I", "ip-pool", "Size of random IP pool (default: 1000)")
	flaggy.Bool(&outputJSON, "j", "json", "Output final metrics as JSON")
	flaggy.Bool(&verbose, "v", "verbose", "Verbose output")
	flaggy.Bool(&follow, "f", "follow", "Follow redirects")
	flaggy.String(&metricsURL, "m", "metrics", "URL to fetch Agbero metrics from (e.g., http://localhost:8080/metrics)")
	flaggy.Bool(&showLatency, "l", "latency", "Show detailed latency distribution")

	flaggy.Parse()

	// Check if serve subcommand was used
	if serveCmd.Used {
		// Run in server mode
		cfg := Config{
			ServeMode:  true,
			PortString: portString,
			StartPort:  startPort,
			EndPort:    endPort,
			TotalPorts: totalPorts,
		}
		runServerMode(&cfg)
		return // This return is correct - it exits main()
	}

	// Run in load test mode (default)
	if len(targets) == 0 {
		flaggy.ShowHelpAndExit("Load test mode requires target URLs")
	}

	// Parse duration for load test
	var dur time.Duration
	if duration != "" {
		var err error
		dur, err = time.ParseDuration(duration)
		if err != nil {
			fmt.Printf("Invalid duration: %v\n", err)
			os.Exit(1) // Use os.Exit instead of returning
		}
	}

	// Parse timeout
	timeoutDur := 30 * time.Second
	if timeout != "" {
		var err error
		timeoutDur, err = time.ParseDuration(timeout)
		if err != nil {
			fmt.Printf("Invalid timeout: %v\n", err)
			os.Exit(1) // Use os.Exit instead of returning
		}
	}

	// Default values
	if concurrency <= 0 {
		concurrency = 10
	}
	if method == "" {
		method = "GET"
	}
	if ipPoolSize <= 0 {
		ipPoolSize = 1000
	}

	config := Config{
		Targets:     targets,
		Concurrency: concurrency,
		Requests:    requests,
		Duration:    dur,
		RateLimit:   rateLimit,
		Method:      method,
		Headers:     headers,
		Body:        body,
		KeepAlive:   keepAlive,
		Timeout:     timeoutDur,
		RandomIPs:   randomIPs,
		IPPoolSize:  ipPoolSize,
		OutputJSON:  outputJSON,
		Verbose:     verbose,
		Follow:      follow,
		MetricsURL:  metricsURL,
		ShowLatency: showLatency,
	}

	// Start the TUI for load test
	startTime = time.Now()

	// Create model first
	model := NewModel(config)

	// Then create the program with the model
	p := tea.NewProgram(&model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	// Run the program
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}

	// Output final metrics as JSON if requested
	if outputJSON {
		snapshot := model.Metrics.Snapshot()
		jsonData, _ := json.MarshalIndent(snapshot, "", "  ")
		fmt.Println(string(jsonData))
	}
}

// main.go - Fix the runLoadTest function signature
func runLoadTest(cfg Config, metrics *Metrics, msgChan chan tea.Msg, totalRequests uint64) {
	// Remove the "return func" part and just have the function body

	var requestCounter uint64
	var wg sync.WaitGroup

	// Start workers
	workers := make([]*Worker, cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		worker := NewWorker(i+1, &cfg, metrics, &requestCounter)
		workers[i] = worker
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()
			w.Run()
		}(worker)
	}

	// Send initial metrics
	msgChan <- metricsMsg{}

	// Start metrics updater
	stopMetrics := make(chan struct{})
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond) // Update twice per second
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Calculate requests per second
				total := metrics.TotalRequests.Load()
				timeSinceStart := time.Since(startTime).Seconds()
				if timeSinceStart > 0 {
					rps := uint64(float64(total) / timeSinceStart)
					metrics.RequestsPerSec.Store(rps)
				}

				// Send metrics update
				msgChan <- metricsMsg{}

				// Send progress update
				if cfg.Requests > 0 {
					completed := atomic.LoadUint64(&requestCounter)
					msgChan <- progressMsg{
						completed: completed,
						total:     totalRequests,
						done:      completed >= totalRequests,
					}
				}
			case <-stopMetrics:
				return
			}
		}
	}()

	// Start log forwarder
	go func() {
		for log := range logQueue {
			msgChan <- logMsg{text: log}
		}
	}()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for completion
	var done bool
	if cfg.Duration > 0 {
		select {
		case <-time.After(cfg.Duration):
			done = true
		case <-sigChan:
			done = true
		}
	} else if cfg.Requests > 0 {
		for !done {
			select {
			case <-sigChan:
				done = true
			default:
				if atomic.LoadUint64(&requestCounter) >= totalRequests {
					done = true
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	} else {
		// Run until interrupted
		<-sigChan
		done = true
	}

	// Stop workers
	for _, worker := range workers {
		close(worker.StopChan)
	}

	// Stop metrics updater
	close(stopMetrics)

	wg.Wait()

	// Send final progress
	if cfg.Requests > 0 {
		msgChan <- progressMsg{
			completed: atomic.LoadUint64(&requestCounter),
			total:     totalRequests,
			done:      true,
		}
	}

	// Send final metrics
	msgChan <- metricsMsg{}

	// Clean up
	close(logQueue)
}
