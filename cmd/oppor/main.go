package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/integrii/flaggy"
	"github.com/olekukonko/ll"
	"golang.org/x/time/rate"
)

var (
	logger = ll.New("opopo", ll.WithFatalExits(true))
)

// =================== CONFIGURATION ===================
type Config struct {
	// Load test config
	Targets     []string      `json:"targets"`
	Concurrency int           `json:"concurrency"`
	Requests    int           `json:"requests"` // 0 = infinite
	Duration    time.Duration `json:"duration"`
	RateLimit   int           `json:"rate_limit"` // reqs/sec, 0 = unlimited
	Method      string        `json:"method"`
	Headers     []string      `json:"headers"`
	Body        string        `json:"body"`
	KeepAlive   bool          `json:"keep_alive"`
	Timeout     time.Duration `json:"timeout"`
	RandomIPs   bool          `json:"random_ips"`
	IPPoolSize  int           `json:"ip_pool_size"`
	OutputJSON  bool          `json:"output_json"`
	Verbose     bool          `json:"verbose"`
	Follow      bool          `json:"follow"`
	MetricsURL  string        `json:"metrics_url"`
	ShowLatency bool          `json:"show_latency"`

	// Server config
	ServeMode  bool     `json:"serve_mode"`
	Ports      []string `json:"ports"`
	StartPort  int      `json:"start_port"`
	EndPort    int      `json:"end_port"`
	TotalPorts int      `json:"total_ports"`
	PortString string   `json:"port_string"`
}

// =================== SERVER MODE ===================
type TestServer struct {
	Port         string
	Server       *http.Server
	Started      bool
	StartTime    time.Time
	RequestCount atomic.Uint64
}

func NewTestServer(port string) *TestServer {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Test Server running on port %s\n", port)
		fmt.Fprintf(w, "Request Path: %s\n", r.URL.Path)
		fmt.Fprintf(w, "Query Parameters: %v\n", r.URL.Query())
		fmt.Fprintf(w, "Remote Address: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "Headers:\n")
		for k, v := range r.Header {
			fmt.Fprintf(w, "  %s: %v\n", k, v)
		}
		fmt.Fprintf(w, "\nServer Uptime: %v\n", time.Since(startTime))
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "healthy",
			"port":     port,
			"uptime":   time.Since(startTime).String(),
			"requests": atomic.LoadUint64(&requestCount),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server": map[string]interface{}{
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
		Port: port,
		Server: &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		},
		StartTime: time.Now(),
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

// =================== LOAD TEST METRICS ===================
type Metrics struct {
	TotalRequests     atomic.Uint64
	SuccessCount      atomic.Uint64
	ErrorCount        atomic.Uint64
	TotalLatency      atomic.Uint64 // microseconds
	MinLatency        atomic.Uint64
	MaxLatency        atomic.Uint64
	TotalBytes        atomic.Uint64
	RequestsPerSec    atomic.Uint64
	ActiveConnections atomic.Int32

	// Status code distribution
	StatusCode2xx atomic.Uint64
	StatusCode3xx atomic.Uint64
	StatusCode4xx atomic.Uint64
	StatusCode5xx atomic.Uint64

	// Latency histogram
	LatencyBuckets [10]atomic.Uint64 // 0-10ms, 10-50ms, 50-100ms, 100-250ms, 250-500ms, 500-1000ms, 1-2s, 2-5s, 5-10s, 10s+
}

func (m *Metrics) Record(latency time.Duration, status int, bytes int64, err error) {
	m.TotalRequests.Add(1)
	m.TotalBytes.Add(uint64(bytes))

	latencyUs := uint64(latency.Microseconds())
	m.TotalLatency.Add(latencyUs)

	// Update min/max
	currentMin := m.MinLatency.Load()
	if currentMin == 0 || latencyUs < currentMin {
		m.MinLatency.Store(latencyUs)
	}
	currentMax := m.MaxLatency.Load()
	if latencyUs > currentMax {
		m.MaxLatency.Store(latencyUs)
	}

	// Update status codes
	if err != nil {
		m.ErrorCount.Add(1)
	} else {
		m.SuccessCount.Add(1)
		switch {
		case status >= 200 && status < 300:
			m.StatusCode2xx.Add(1)
		case status >= 300 && status < 400:
			m.StatusCode3xx.Add(1)
		case status >= 400 && status < 500:
			m.StatusCode4xx.Add(1)
		case status >= 500:
			m.StatusCode5xx.Add(1)
		}
	}

	// Update latency bucket
	latencyMs := latency.Milliseconds()
	switch {
	case latencyMs < 10:
		m.LatencyBuckets[0].Add(1)
	case latencyMs < 50:
		m.LatencyBuckets[1].Add(1)
	case latencyMs < 100:
		m.LatencyBuckets[2].Add(1)
	case latencyMs < 250:
		m.LatencyBuckets[3].Add(1)
	case latencyMs < 500:
		m.LatencyBuckets[4].Add(1)
	case latencyMs < 1000:
		m.LatencyBuckets[5].Add(1)
	case latencyMs < 2000:
		m.LatencyBuckets[6].Add(1)
	case latencyMs < 5000:
		m.LatencyBuckets[7].Add(1)
	case latencyMs < 10000:
		m.LatencyBuckets[8].Add(1)
	default:
		m.LatencyBuckets[9].Add(1)
	}
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	total := m.TotalRequests.Load()
	success := m.SuccessCount.Load()
	errors := m.ErrorCount.Load()

	var avgLatency float64
	if success > 0 {
		avgLatency = float64(m.TotalLatency.Load()) / float64(success) / 1000.0 // in ms
	}

	return MetricsSnapshot{
		TotalRequests:     total,
		SuccessCount:      success,
		ErrorCount:        errors,
		SuccessRate:       float64(success) / float64(total) * 100,
		AvgLatencyMs:      avgLatency,
		MinLatencyMs:      float64(m.MinLatency.Load()) / 1000.0,
		MaxLatencyMs:      float64(m.MaxLatency.Load()) / 1000.0,
		RequestsPerSec:    m.RequestsPerSec.Load(),
		ThroughputMBps:    float64(m.TotalBytes.Load()) / (1024 * 1024),
		ActiveConnections: m.ActiveConnections.Load(),
		StatusCode2xx:     m.StatusCode2xx.Load(),
		StatusCode3xx:     m.StatusCode3xx.Load(),
		StatusCode4xx:     m.StatusCode4xx.Load(),
		StatusCode5xx:     m.StatusCode5xx.Load(),
		TotalBytes:        m.TotalBytes.Load(),
	}
}

type MetricsSnapshot struct {
	TotalRequests     uint64  `json:"total_requests"`
	SuccessCount      uint64  `json:"success_count"`
	ErrorCount        uint64  `json:"error_count"`
	SuccessRate       float64 `json:"success_rate"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	MinLatencyMs      float64 `json:"min_latency_ms"`
	MaxLatencyMs      float64 `json:"max_latency_ms"`
	RequestsPerSec    uint64  `json:"requests_per_sec"`
	ThroughputMBps    float64 `json:"throughput_mbps"`
	ActiveConnections int32   `json:"active_connections"`
	StatusCode2xx     uint64  `json:"status_2xx"`
	StatusCode3xx     uint64  `json:"status_3xx"`
	StatusCode4xx     uint64  `json:"status_4xx"`
	StatusCode5xx     uint64  `json:"status_5xx"`
	TotalBytes        uint64  `json:"total_bytes"`
}

// =================== LOAD TEST WORKER ===================
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

	// Log if verbose
	if w.Config.Verbose {
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

// =================== TUI MODEL FOR LOAD TEST ===================
type Model struct {
	Config    Config
	Metrics   *Metrics
	Running   bool
	StartTime time.Time
	Duration  time.Duration

	// UI Components
	Progress    progress.Model
	Spinner     spinner.Model
	MetricsView viewport.Model
	LogView     viewport.Model
	Table       table.Model

	// Data
	Logs       []string
	LastUpdate time.Time
	Width      int
	Height     int

	// Control
	Quit bool

	// External metrics from Agbero
	AgberoMetrics map[string]interface{}

	// For progress tracking
	TotalRequests     uint64
	CompletedRequests uint64

	// Channel for sending messages from goroutines
	msgChan chan tea.Msg
}

func NewModel(cfg Config) Model {
	// Progress bar
	prog := progress.New(progress.WithDefaultGradient())
	prog.Width = 40

	// Spinner
	spin := spinner.New()
	spin.Spinner = spinner.Dot

	// Metrics view
	metricsView := viewport.New(80, 10)
	metricsView.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1)

	// Log view
	logView := viewport.New(80, 10)
	logView.Style = lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("241")).
		Padding(0, 1)

	// Create table for latency distribution
	columns := []table.Column{
		{Title: "Latency Range", Width: 15},
		{Title: "Count", Width: 10},
		{Title: "Percentage", Width: 15},
	}

	rows := make([]table.Row, 10)
	ranges := []string{
		"< 10ms", "10-50ms", "50-100ms", "100-250ms",
		"250-500ms", "500ms-1s", "1-2s", "2-5s",
		"5-10s", "> 10s",
	}

	for i, r := range ranges {
		rows[i] = table.Row{r, "0", "0%"}
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(false),
		table.WithHeight(12),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return Model{
		Config:        cfg,
		Metrics:       &Metrics{},
		Running:       true,
		StartTime:     time.Now(),
		Progress:      prog,
		Spinner:       spin,
		MetricsView:   metricsView,
		LogView:       logView,
		Table:         t,
		Logs:          []string{},
		LastUpdate:    time.Now(),
		msgChan:       make(chan tea.Msg, 100),
		TotalRequests: uint64(cfg.Requests),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.Spinner.Tick,
		m.startLoadTest(),
		m.listenForMessages(),
		updateMetrics(),
		fetchAgberoMetrics(m.Config.MetricsURL),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.Quit = true
			return m, tea.Quit
		case "up", "k":
			m.MetricsView.LineUp(1)
			m.LogView.LineUp(1)
		case "down", "j":
			m.MetricsView.LineDown(1)
			m.LogView.LineDown(1)
		case " ":
			m.Running = !m.Running
		case "r", "R":
			// Refresh external metrics
			if m.Config.MetricsURL != "" {
				return m, fetchAgberoMetrics(m.Config.MetricsURL)
			}
		}
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.MetricsView.Width = msg.Width - 4
		m.MetricsView.Height = 12
		m.LogView.Width = msg.Width - 4
		m.LogView.Height = 10
		m.Progress.Width = min(40, msg.Width-10)

		// Adjust table size
		m.Table.SetWidth(msg.Width - 4)
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd
	case progressMsg:
		if msg.done {
			m.Running = false
			m.Progress.SetPercent(1.0)
			return m, tea.Quit
		} else {
			m.CompletedRequests = msg.completed
			if msg.total > 0 {
				progressPercent := float64(msg.completed) / float64(msg.total)
				m.Progress.SetPercent(progressPercent)
			}
		}
		return m, nil
	case metricsMsg:
		m.LastUpdate = time.Now()
		// Update metrics view
		snapshot := m.Metrics.Snapshot()
		m.updateMetricsView(snapshot)
		m.updateLatencyTable()

		// Check if test should end
		if m.Config.Duration > 0 && time.Since(m.StartTime) >= m.Config.Duration {
			m.Running = false
			return m, tea.Quit
		}
		if m.Config.Requests > 0 && snapshot.TotalRequests >= uint64(m.Config.Requests) {
			m.Running = false
			return m, tea.Quit
		}

		// Schedule next update
		return m, updateMetricsAfter(500 * time.Millisecond)
	case logMsg:
		m.Logs = append(m.Logs, msg.text)
		if len(m.Logs) > 100 {
			m.Logs = m.Logs[1:]
		}
		m.updateLogView()
	case agberoMetricsMsg:
		m.AgberoMetrics = msg.metrics
		// Refresh every 5 seconds if metrics URL is set
		if m.Config.MetricsURL != "" {
			return m, tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
				return fetchAgberoMetrics(m.Config.MetricsURL)()
			})
		}
	case tea.Cmd:
		// Handle commands from channel
		return m, msg
	}

	// Update viewports
	var cmds []tea.Cmd
	m.MetricsView, _ = m.MetricsView.Update(msg)
	m.LogView, _ = m.LogView.Update(msg)

	return m, tea.Batch(cmds...)
}

func (m *Model) updateMetricsView(snapshot MetricsSnapshot) {
	duration := time.Since(m.StartTime).Seconds()
	if duration == 0 {
		duration = 1
	}

	totalRPS := uint64(float64(snapshot.TotalRequests) / duration)
	throughput := float64(snapshot.TotalBytes) / duration / (1024 * 1024) // MB/s

	// Build metrics content
	var contentBuilder strings.Builder

	contentBuilder.WriteString("┌─────────────────┐\n")
	contentBuilder.WriteString("│ Load Test Status │\n")
	contentBuilder.WriteString("└─────────────────┘\n\n")

	contentBuilder.WriteString(fmt.Sprintf("Duration:    %s\n", time.Since(m.StartTime).Round(time.Second)))
	contentBuilder.WriteString(fmt.Sprintf("Requests:    %d (%d/s)\n", snapshot.TotalRequests, totalRPS))
	contentBuilder.WriteString(fmt.Sprintf("Success:     %d (%.1f%%)\n", snapshot.SuccessCount, snapshot.SuccessRate))
	contentBuilder.WriteString(fmt.Sprintf("Errors:      %d\n", snapshot.ErrorCount))
	contentBuilder.WriteString(fmt.Sprintf("Active:      %d\n\n", snapshot.ActiveConnections))

	contentBuilder.WriteString("Latency (ms):\n")
	contentBuilder.WriteString(fmt.Sprintf("  Avg: %.1f  Min: %.1f  Max: %.1f\n\n",
		snapshot.AvgLatencyMs, snapshot.MinLatencyMs, snapshot.MaxLatencyMs))

	contentBuilder.WriteString(fmt.Sprintf("Throughput:  %.2f MB/s\n\n", throughput))

	contentBuilder.WriteString("Status Codes:\n")
	contentBuilder.WriteString(fmt.Sprintf("  2xx: %d  3xx: %d  4xx: %d  5xx: %d\n",
		snapshot.StatusCode2xx, snapshot.StatusCode3xx, snapshot.StatusCode4xx, snapshot.StatusCode5xx))

	// Add Agbero metrics if available
	if m.AgberoMetrics != nil {
		contentBuilder.WriteString("\n┌─────────────────────┐\n")
		contentBuilder.WriteString("│ Agbero Proxy Stats │\n")
		contentBuilder.WriteString("└─────────────────────┘\n")

		if hosts, ok := m.AgberoMetrics["hosts"].(map[string]interface{}); ok {
			for host, data := range hosts {
				if hostData, ok := data.(map[string]interface{}); ok {
					if totalReqs, ok := hostData["total_reqs"].(float64); ok && totalReqs > 0 {
						contentBuilder.WriteString(fmt.Sprintf("\n%s:\n", host))
						contentBuilder.WriteString(fmt.Sprintf("  Requests: %.0f\n", totalReqs))

						if avgP99, ok := hostData["avg_p99_us"].(float64); ok {
							contentBuilder.WriteString(fmt.Sprintf("  P99 Latency: %.1fms\n", avgP99/1000))
						}

						if backends, ok := hostData["total_backends"].(float64); ok {
							contentBuilder.WriteString(fmt.Sprintf("  Backends: %.0f\n", backends))
						}
					}
				}
			}
		}
	}

	m.MetricsView.SetContent(contentBuilder.String())
}

func (m *Model) updateLatencyTable() {
	total := m.Metrics.TotalRequests.Load()
	if total == 0 {
		return
	}

	rows := make([]table.Row, 10)
	ranges := []string{
		"< 10ms", "10-50ms", "50-100ms", "100-250ms",
		"250-500ms", "500ms-1s", "1-2s", "2-5s",
		"5-10s", "> 10s",
	}

	for i := 0; i < 10; i++ {
		count := m.Metrics.LatencyBuckets[i].Load()
		percentage := float64(count) / float64(total) * 100
		rows[i] = table.Row{
			ranges[i],
			strconv.FormatUint(count, 10),
			fmt.Sprintf("%.1f%%", percentage),
		}
	}

	m.Table.SetRows(rows)
}

func (m *Model) updateLogView() {
	if len(m.Logs) == 0 {
		return
	}

	// Show last 10 logs
	start := max(0, len(m.Logs)-10)
	logContent := strings.Join(m.Logs[start:], "\n")
	m.LogView.SetContent(logContent)
	m.LogView.GotoBottom()
}

func (m Model) View() string {
	if m.Quit {
		return "Test completed. Press Ctrl+C to exit.\n"
	}

	if m.Width == 0 {
		return "Initializing..."
	}

	// Header
	header := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true).
		Padding(0, 1).
		Render("🚀 OPPOR - Load Testing Tool")

	// Status line
	status := "RUNNING"
	statusColor := lipgloss.Color("46") // Green
	if !m.Running {
		status = "PAUSED"
		statusColor = lipgloss.Color("214") // Orange
	}
	statusLine := lipgloss.NewStyle().
		Foreground(statusColor).
		Render(fmt.Sprintf("%s %s", m.Spinner.View(), status))

	// Progress section
	progressPercent := m.Progress.Percent()
	progressText := ""
	if m.TotalRequests > 0 {
		progressText = fmt.Sprintf("Progress: %s (%d/%d)",
			m.Progress.ViewAs(progressPercent),
			m.CompletedRequests,
			m.TotalRequests)
	} else {
		progressText = fmt.Sprintf("Progress: %s", m.Progress.ViewAs(progressPercent))
	}

	// Layout
	var sections []string

	// Top row: Header and status
	topRow := lipgloss.JoinHorizontal(
		lipgloss.Left,
		header,
		strings.Repeat(" ", max(0, m.Width-lipgloss.Width(header)-lipgloss.Width(statusLine)-10)),
		statusLine,
	)

	sections = append(sections, topRow)
	sections = append(sections, "")

	// Metrics and progress
	metricsAndProgress := lipgloss.JoinVertical(
		lipgloss.Left,
		m.MetricsView.View(),
		"",
		progressText,
	)

	sections = append(sections, metricsAndProgress)
	sections = append(sections, "")

	// Latency distribution table (if enabled)
	if m.Config.ShowLatency {
		tableTitle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("99")).
			Bold(true).
			Render("Latency Distribution")
		sections = append(sections, tableTitle)
		sections = append(sections, m.Table.View())
		sections = append(sections, "")
	}

	// Logs (if verbose)
	if m.Config.Verbose {
		logTitle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("242")).
			Render("Recent Logs")
		sections = append(sections, logTitle)
		sections = append(sections, m.LogView.View())
		sections = append(sections, "")
	}

	// Footer with controls
	var controls []string
	controls = append(controls, "Press 'q' to quit | 'space' to pause/resume | '↑/↓' to scroll")
	if m.Config.MetricsURL != "" {
		controls = append(controls, "'r' to refresh Agbero metrics")
	}

	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render(strings.Join(controls, " | "))

	sections = append(sections, footer)

	return lipgloss.NewStyle().
		Width(m.Width).
		Padding(1).
		Render(strings.Join(sections, "\n"))
}

// =================== TEA MESSAGES ===================
type progressMsg struct {
	completed uint64
	total     uint64
	done      bool
}

type metricsMsg struct{}

type logMsg struct {
	text string
}

type agberoMetricsMsg struct {
	metrics map[string]interface{}
}

// =================== TEA COMMANDS ===================
func (m *Model) startLoadTest() tea.Cmd {
	return func() tea.Msg {
		go func() {
			runLoadTest(m.Config, m.Metrics, m.msgChan, m.TotalRequests)
		}()
		return nil
	}
}

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-m.msgChan:
			return msg
		default:
			return nil
		}
	}
}

func updateMetrics() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return metricsMsg{}
	})
}

func updateMetricsAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return metricsMsg{}
	})
}

func fetchAgberoMetrics(url string) tea.Cmd {
	return func() tea.Msg {
		if url == "" {
			return nil
		}

		metrics, err := fetchExternalMetrics(url)
		if err != nil {
			logQueue <- fmt.Sprintf("Failed to fetch Agbero metrics: %v", err)
			return nil
		}

		return agberoMetricsMsg{metrics: metrics}
	}
}

// =================== LOAD TEST RUNNER ===================
var logQueue = make(chan string, 1000)

func runLoadTest(cfg Config, metrics *Metrics, msgChan chan tea.Msg, totalRequests uint64) {
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

	// Start metrics updater
	stopMetrics := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
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

	// Clean up
	close(logQueue)
}

// =================== GLOBAL VARIABLES ===================
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

// =================== MAIN ===================
func main() {
	flaggy.SetName("oppor")
	flaggy.SetDescription("Open Performance & Proxy Observer - Test server and load testing tool")
	flaggy.SetVersion("1.0.0")

	// Mode selection
	flaggy.Bool(&serveMode, "", "serve", "Run in server mode (create test servers)")

	// Server mode flags
	flaggy.String(&portString, "p", "port", "Comma-separated ports (e.g., 8080,8081,8082)")
	flaggy.Int(&startPort, "s", "start", "Start port number")
	flaggy.Int(&endPort, "e", "end", "End port number (for range)")
	flaggy.Int(&totalPorts, "t", "total", "Number of ports from start")

	// Load test flags
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

	// Determine mode
	if serveMode {
		// Run in server mode
		cfg := Config{
			ServeMode:  true,
			PortString: portString,
			StartPort:  startPort,
			EndPort:    endPort,
			TotalPorts: totalPorts,
		}
		runServerMode(&cfg)
		return
	}

	// Run in load test mode
	if len(targets) == 0 {
		// Show help based on mode
		if serveMode {
			flaggy.ShowHelpAndExit("Server mode requires port configuration")
		} else {
			flaggy.ShowHelpAndExit("Load test mode requires target URLs")
		}
	}

	// Parse duration for load test
	var dur time.Duration
	if duration != "" {
		var err error
		dur, err = time.ParseDuration(duration)
		if err != nil {
			fmt.Printf("Invalid duration: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse timeout
	timeoutDur := 30 * time.Second
	if timeout != "" {
		var err error
		timeoutDur, err = time.ParseDuration(timeout)
		if err != nil {
			fmt.Printf("Invalid timeout: %v\n", err)
			os.Exit(1)
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
	p := tea.NewProgram(NewModel(config), tea.WithAltScreen(), tea.WithMouseCellMotion())

	finalModel, err := p.Run()
	if err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}

	// Output final metrics as JSON if requested
	if outputJSON {
		if model, ok := finalModel.(Model); ok {
			snapshot := model.Metrics.Snapshot()
			jsonData, _ := json.MarshalIndent(snapshot, "", "  ")
			fmt.Println(string(jsonData))
		}
	}
}

// =================== UTILITY FUNCTIONS ===================
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Fetch external metrics from Agbero proxy
func fetchExternalMetrics(url string) (map[string]interface{}, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var metrics map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, err
	}

	return metrics, nil
}
