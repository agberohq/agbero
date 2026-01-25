package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

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
	// Simple test view
	return fmt.Sprintf(`
OPPOR Load Test Running
Target: %s
Concurrency: %d
Requests: %d
Time: %v
Press 'q' to quit
`,
		m.Config.Targets[0],
		m.Config.Concurrency,
		m.Config.Requests,
		time.Since(m.StartTime).Round(time.Second))
}

func (m *Model) startLoadTest() tea.Cmd {
	return func() tea.Msg {
		// Start load test in goroutine
		go func() {
			runLoadTest(m.Config, m.Metrics, m.msgChan, m.TotalRequests)
		}()

		// Start listening for messages
		return m.listenForMessages()
	}
}

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-m.msgChan:
			switch msg := msg.(type) {
			case progressMsg:
				return msg
			case logMsg:
				return msg
			case metricsMsg:
				return msg
			case agberoMetricsMsg:
				return msg
			default:
				return nil
			}
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	}
}
