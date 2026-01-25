// cmd/lab/main.go
package main

import (
	"bytes"
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
	"golang.org/x/time/rate"
)

// =================== CONFIGURATION ===================
type Config struct {
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
}

// =================== METRICS ===================
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
}

// =================== WORKER ===================
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

	req, err := http.NewRequest(w.Config.Method, target, nil)
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

	// Add body if POST/PUT
	if w.Config.Body != "" && (w.Config.Method == "POST" || w.Config.Method == "PUT") {
		req.Body = io.NopCloser(strings.NewReader(w.Config.Body))
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
		LogQueue <- logMsg
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

// =================== TUI MODEL ===================
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
		Config:      cfg,
		Metrics:     &Metrics{},
		Running:     true,
		StartTime:   time.Now(),
		Progress:    prog,
		Spinner:     spin,
		MetricsView: metricsView,
		LogView:     logView,
		Table:       t,
		Logs:        []string{},
		LastUpdate:  time.Now(),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.Spinner.Tick,
		startLoadTest(m.Config, m.Metrics),
		listenForLogs(),
		updateMetrics(),
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
		} else {
			progressPercent := float64(msg.completed) / float64(msg.total)
			m.Progress.SetPercent(progressPercent)
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

	throughput := float64(snapshot.TotalBytes) / duration / (1024 * 1024) // MB/s

	content := fmt.Sprintf(
		`┌─────────────────┐
│ Load Test Status │
└─────────────────┘

Duration:    %s
Requests:    %d (%d/s)
Success:     %d (%.1f%%)
Errors:      %d
Active:      %d

Latency (ms):
  Avg: %.1f  Min: %.1f  Max: %.1f

Throughput:  %.2f MB/s

Status Codes:
  2xx: %d  3xx: %d  4xx: %d  5xx: %d`,
		time.Since(m.StartTime).Round(time.Second),
		snapshot.TotalRequests,
		uint64(float64(snapshot.TotalRequests)/duration),
		snapshot.SuccessCount,
		snapshot.SuccessRate,
		snapshot.ErrorCount,
		snapshot.ActiveConnections,
		snapshot.AvgLatencyMs,
		snapshot.MinLatencyMs,
		snapshot.MaxLatencyMs,
		throughput,
		snapshot.StatusCode2xx,
		snapshot.StatusCode3xx,
		snapshot.StatusCode4xx,
		snapshot.StatusCode5xx,
	)

	m.MetricsView.SetContent(content)
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
		Render("🚀 LAB - Load Testing Tool")

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
	progressSection := fmt.Sprintf("Progress: %s", m.Progress.View())

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
		progressSection,
	)

	sections = append(sections, metricsAndProgress)
	sections = append(sections, "")

	// Latency distribution table
	tableTitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("99")).
		Bold(true).
		Render("Latency Distribution")
	sections = append(sections, tableTitle)
	sections = append(sections, m.Table.View())
	sections = append(sections, "")

	// Logs
	logTitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("242")).
		Render("Recent Logs")
	sections = append(sections, logTitle)
	sections = append(sections, m.LogView.View())

	// Footer
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Render("Press 'q' to quit | 'space' to pause/resume | '↑/↓' to scroll")

	sections = append(sections, "")
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

// =================== TEA COMMANDS ===================
func startLoadTest(cfg Config, metrics *Metrics) tea.Cmd {
	return func() tea.Msg {
		go runLoadTest(cfg, metrics)
		return nil
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

func listenForLogs() tea.Cmd {
	return func() tea.Msg {
		for msg := range LogQueue {
			return logMsg{text: msg}
		}
		return nil
	}
}

// =================== LOAD TEST RUNNER ===================
var LogQueue = make(chan string, 1000)

func runLoadTest(cfg Config, metrics *Metrics) {
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
			case <-stopMetrics:
				return
			}
		}
	}()

	// Wait for completion
	if cfg.Duration > 0 {
		time.Sleep(cfg.Duration)
	} else if cfg.Requests > 0 {
		for atomic.LoadUint64(&requestCounter) < uint64(cfg.Requests) {
			time.Sleep(100 * time.Millisecond)
		}
	} else {
		// Run until interrupted
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
	}

	// Stop workers
	for _, worker := range workers {
		close(worker.StopChan)
	}

	// Stop metrics updater
	close(stopMetrics)

	wg.Wait()
}

// =================== CLI ===================
var (
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
)

var startTime time.Time

func main() {
	flaggy.SetName("lab")
	flaggy.SetDescription("Load testing tool with real-time TUI")
	flaggy.SetVersion("1.0.0")

	// Required
	flaggy.StringSlice(&targets, "t", "target", "Target URLs (comma-separated or repeated)")

	// Load configuration
	flaggy.Int(&concurrency, "c", "concurrency", "Number of concurrent workers (default: 10)")
	flaggy.Int(&requests, "n", "requests", "Total number of requests (0 = infinite)")
	flaggy.String(&duration, "d", "duration", "Test duration (e.g., 30s, 5m, 1h)")
	flaggy.Int(&rateLimit, "r", "rate", "Requests per second per worker (0 = unlimited)")

	// Request configuration
	flaggy.String(&method, "X", "method", "HTTP method (default: GET)")
	flaggy.StringSlice(&headers, "H", "header", "HTTP headers (key:value)")
	flaggy.String(&body, "b", "body", "Request body")
	flaggy.Bool(&keepAlive, "k", "keepalive", "Use HTTP keep-alive")

	// Network configuration
	flaggy.String(&timeout, "T", "timeout", "Request timeout (default: 30s)")
	flaggy.Bool(&randomIPs, "i", "random-ips", "Use random source IPs")
	flaggy.Int(&ipPoolSize, "I", "ip-pool", "Size of random IP pool (default: 1000)")

	// Output configuration
	flaggy.Bool(&outputJSON, "j", "json", "Output final metrics as JSON")
	flaggy.Bool(&verbose, "v", "verbose", "Verbose output")
	flaggy.Bool(&follow, "f", "follow", "Follow redirects")
	flaggy.String(&metricsURL, "m", "metrics", "URL to fetch external metrics from")
	flaggy.Bool(&showLatency, "l", "latency", "Show detailed latency distribution")

	flaggy.Parse()

	if len(targets) == 0 {
		flaggy.ShowHelpAndExit("At least one target URL is required")
	}

	// Parse duration
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

	// Start the TUI
	startTime = time.Now()
	p := tea.NewProgram(NewModel(config), tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running TUI: %v\n", err)
		os.Exit(1)
	}

	// Output final metrics as JSON if requested
	if outputJSON {
		metrics := &Metrics{}
		snapshot := metrics.Snapshot()
		jsonData, _ := json.MarshalIndent(snapshot, "", "  ")
		fmt.Println(string(jsonData))
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

// Additional utility for external metrics
func fetchExternalMetrics(url string) (map[string]interface{}, error) {
	client := &http.Client{Timeout: 5 * time.Second}
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
