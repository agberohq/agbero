// model.go
package main

import (
	"fmt"
	"math"
	"sort"
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

// ---------- Styles (keep in THIS file so they exist) ----------

var (
	styleTopBar = lipgloss.NewStyle().
			Padding(0, 1).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true)

	stylePanel = lipgloss.NewStyle().
			Padding(0, 1).
			BorderStyle(lipgloss.RoundedBorder())

	stylePanelTitle = lipgloss.NewStyle().
			Bold(true)

	styleMuted = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	styleGood = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

	styleBad = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	styleWarn = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214"))
)

// ---------- Bubble Tea Messages ----------

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
	metricsView := viewport.New(80, 12)
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

	// Table (kept for future / optional)
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
		msgChan:       make(chan tea.Msg, 1000),
		TotalRequests: uint64(cfg.Requests),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.Spinner.Tick,
		m.startLoadTest(),
		m.listenForMessages(),
		updateMetricsAfter(200*time.Millisecond),
		fetchAgberoMetrics(m.Config.MetricsURL),
	)
}

// IMPORTANT: stays open after DONE (until 'q')
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Always keep listening for goroutine messages.
	cmds := []tea.Cmd{m.listenForMessages()}

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

		case "r", "R":
			if m.Config.MetricsURL != "" {
				cmds = append(cmds, fetchAgberoMetrics(m.Config.MetricsURL))
			}
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height

		// We'll also resize in View(), but keep sane defaults here
		m.MetricsView.Width = msg.Width - 4
		m.MetricsView.Height = 12

		m.LogView.Width = msg.Width - 4
		m.LogView.Height = max(6, msg.Height-20)

		m.Progress.Width = min(40, msg.Width-10)
		m.Table.SetWidth(msg.Width - 4)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		cmds = append(cmds, cmd)

	case progressMsg:
		m.CompletedRequests = msg.completed

		if msg.total > 0 {
			m.Progress.SetPercent(float64(msg.completed) / float64(msg.total))
		}

		// Done: do NOT quit; stay open
		if msg.done {
			m.Running = false
			m.Progress.SetPercent(1.0) // force 100% on completion
		}

	case metricsMsg:
		m.LastUpdate = time.Now()

		snap := m.Metrics.Snapshot()
		m.updateMetricsView(snap)
		m.updateLatencyTable()

		// Stop conditions: mark done only; do NOT quit
		if m.Config.Duration > 0 && time.Since(m.StartTime) >= m.Config.Duration {
			m.Running = false
			if m.Config.Requests > 0 {
				m.Progress.SetPercent(1.0)
			}
		}
		if m.Config.Requests > 0 && snap.TotalRequests >= uint64(m.Config.Requests) {
			m.Running = false
			m.Progress.SetPercent(1.0)
		}

		// Keep refreshing (cheap). You can gate this by m.Running if you want.
		cmds = append(cmds, updateMetricsAfter(500*time.Millisecond))

	case logMsg:
		m.Logs = append(m.Logs, msg.text)
		if len(m.Logs) > 300 {
			m.Logs = m.Logs[len(m.Logs)-300:]
		}
		m.updateLogView()

	case agberoMetricsMsg:
		m.AgberoMetrics = msg.metrics

		// Refresh every 5 seconds if configured
		if m.Config.MetricsURL != "" {
			cmds = append(cmds, tea.Tick(5*time.Second, func(time.Time) tea.Msg {
				return fetchAgberoMetrics(m.Config.MetricsURL)()
			}))
		}
	}

	// Let viewports handle wheel scroll and such too
	var cmd tea.Cmd
	m.MetricsView, cmd = m.MetricsView.Update(msg)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}
	m.LogView, cmd = m.LogView.Update(msg)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// ---------- Dashboard View ----------

func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		// Bubble Tea sends a WindowSizeMsg shortly after start
		return "Initializing..."
	}

	snap := m.Metrics.Snapshot()

	// ---- Top bar ----
	status := "RUNNING"
	statusStyle := styleGood
	if !m.Running {
		status = "DONE (press q to quit)"
		statusStyle = styleWarn
	}
	if snap.ErrorCount > 0 {
		statusStyle = styleBad
	}

	target := "-"
	if len(m.Config.Targets) > 0 {
		if len(m.Config.Targets) == 1 {
			target = m.Config.Targets[0]
		} else {
			target = fmt.Sprintf("%s (+%d)", m.Config.Targets[0], len(m.Config.Targets)-1)
		}
	}

	elapsed := time.Since(m.StartTime).Round(time.Second)

	rps := snap.RequestsPerSec
	if rps == 0 {
		sec := math.Max(1, time.Since(m.StartTime).Seconds())
		rps = uint64(float64(snap.TotalRequests) / sec)
	}

	top := styleTopBar.Render(
		lipgloss.JoinHorizontal(lipgloss.Top,
			statusStyle.Render(" "+status+" "),
			styleMuted.Render("  target: ")+target,
			styleMuted.Render("  elapsed: ")+elapsed.String(),
			styleMuted.Render("  rps: ")+fmt.Sprintf("%d", rps),
			styleMuted.Render("  errors: ")+fmt.Sprintf("%d", snap.ErrorCount),
		),
	)

	// ---- Progress line ----
	progressLine := ""
	if m.Config.Requests > 0 {
		progressLine = fmt.Sprintf(
			"%s %s %s",
			styleMuted.Render("Progress:"),
			m.Progress.View(),
			styleMuted.Render(fmt.Sprintf(" %d/%d", m.CompletedRequests, m.TotalRequests)),
		)
	} else if m.Config.Duration > 0 {
		remaining := m.Config.Duration - time.Since(m.StartTime)
		if remaining < 0 {
			remaining = 0
		}
		progressLine = fmt.Sprintf("%s %s", styleMuted.Render("Time left:"), remaining.Round(time.Second))
	} else {
		progressLine = styleMuted.Render("Mode: infinite (q / Ctrl+C to quit)")
	}

	// ---- Layout calculations ----
	bodyHeight := m.Height - lipgloss.Height(top) - 3 // top + progress + spacing
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	logsHeight := clamp(bodyHeight/3, 7, 14)
	panelsHeight := bodyHeight - logsHeight - 1

	gap := 2
	leftW := (m.Width - gap) / 2
	rightW := m.Width - gap - leftW

	leftPanel := m.renderMetricsPanel(snap, panelsHeight, leftW)
	rightPanel := m.renderLatencyPanel(panelsHeight, rightW)

	panelsRow := lipgloss.JoinHorizontal(lipgloss.Top,
		leftPanel,
		lipgloss.NewStyle().Width(gap).Render(""),
		rightPanel,
	)

	logsPanel := m.renderLogsPanel(logsHeight, m.Width)

	var out strings.Builder
	out.WriteString(top)
	out.WriteString("\n")
	out.WriteString(progressLine)
	out.WriteString("\n\n")
	out.WriteString(panelsRow)
	out.WriteString("\n\n")
	out.WriteString(logsPanel)

	return out.String()
}

func (m Model) renderMetricsPanel(snap MetricsSnapshot, h, w int) string {
	title := stylePanelTitle.Render("Load Test")
	var body strings.Builder

	sec := math.Max(1, time.Since(m.StartTime).Seconds())
	throughput := float64(snap.TotalBytes) / sec / (1024 * 1024)

	body.WriteString(fmt.Sprintf("%s %d\n", styleMuted.Render("Requests:"), snap.TotalRequests))
	body.WriteString(fmt.Sprintf("%s %d (%.1f%%)\n", styleMuted.Render("Success:"), snap.SuccessCount, snap.SuccessRate))
	body.WriteString(fmt.Sprintf("%s %d\n", styleMuted.Render("Errors:"), snap.ErrorCount))
	body.WriteString(fmt.Sprintf("%s %d\n\n", styleMuted.Render("Active:"), snap.ActiveConnections))

	body.WriteString(stylePanelTitle.Render("Latency (ms)") + "\n")
	body.WriteString(fmt.Sprintf("avg: %.1f   min: %.1f   max: %.1f\n\n",
		snap.AvgLatencyMs, snap.MinLatencyMs, snap.MaxLatencyMs))

	body.WriteString(stylePanelTitle.Render("Traffic") + "\n")
	body.WriteString(fmt.Sprintf("rps: %d\n", snap.RequestsPerSec))
	body.WriteString(fmt.Sprintf("throughput: %.2f MB/s\n\n", throughput))

	body.WriteString(stylePanelTitle.Render("Status Codes") + "\n")
	body.WriteString(fmt.Sprintf("2xx: %d   3xx: %d\n", snap.StatusCode2xx, snap.StatusCode3xx))
	body.WriteString(fmt.Sprintf("4xx: %d   5xx: %d\n", snap.StatusCode4xx, snap.StatusCode5xx))

	if m.AgberoMetrics != nil {
		body.WriteString("\n\n")
		body.WriteString(stylePanelTitle.Render("Agbero (top hosts)") + "\n")
		body.WriteString(m.renderAgberoSummary(w - 4))
	}

	return stylePanel.Width(w).Height(h).Render(title + "\n\n" + body.String())
}

func (m Model) renderLatencyPanel(h, w int) string {
	title := stylePanelTitle.Render("Latency Distribution")

	total := m.Metrics.TotalRequests.Load()

	graph := renderHistogram(
		[]string{"<10ms", "10-50", "50-100", "100-250", "250-500", "500-1s", "1-2s", "2-5s", "5-10s", ">10s"},
		func(i int) uint64 { return m.Metrics.LatencyBuckets[i].Load() },
		total,
		w-4,
		h-4,
	)

	return stylePanel.Width(w).Height(h).Render(title + "\n\n" + graph)
}

func (m Model) renderLogsPanel(h, w int) string {
	title := stylePanelTitle.Render("Logs")

	// Ensure viewport matches the panel inner size
	m.LogView.Width = w - 4
	m.LogView.Height = h - 4

	content := m.LogView.View()
	if strings.TrimSpace(content) == "" {
		content = styleMuted.Render("No logs yet. Run with -v to see per-request logs.")
	}

	return stylePanel.Width(w).Height(h).Render(title + "\n\n" + content)
}

func (m Model) renderAgberoSummary(maxWidth int) string {
	hosts, ok := m.AgberoMetrics["hosts"].(map[string]interface{})
	if !ok || len(hosts) == 0 {
		return styleMuted.Render("No host data")
	}

	type row struct {
		host      string
		totalReqs float64
		p99us     float64
		backends  float64
	}

	rows := make([]row, 0, len(hosts))
	for host, data := range hosts {
		hostData, ok := data.(map[string]interface{})
		if !ok {
			continue
		}

		r := row{host: host}
		if v, ok := hostData["total_reqs"].(float64); ok {
			r.totalReqs = v
		}
		if v, ok := hostData["avg_p99_us"].(float64); ok {
			r.p99us = v
		}
		if v, ok := hostData["total_backends"].(float64); ok {
			r.backends = v
		}

		rows = append(rows, r)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].totalReqs > rows[j].totalReqs })
	if len(rows) > 6 {
		rows = rows[:6]
	}

	var b strings.Builder
	for _, r := range rows {
		line := fmt.Sprintf("%s reqs=%.0f  p99=%.1fms  backends=%.0f",
			r.host, r.totalReqs, r.p99us/1000.0, r.backends)

		if maxWidth > 0 {
			line = truncate(line, maxWidth)
		}
		b.WriteString(line + "\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// ---------- Existing helpers you already had (kept) ----------

func (m *Model) updateMetricsView(snapshot MetricsSnapshot) {
	duration := time.Since(m.StartTime).Seconds()
	if duration == 0 {
		duration = 1
	}

	totalRPS := uint64(float64(snapshot.TotalRequests) / duration)
	throughput := float64(snapshot.TotalBytes) / duration / (1024 * 1024) // MB/s

	var contentBuilder strings.Builder
	contentBuilder.WriteString("Load Test Status\n\n")
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
	start := max(0, len(m.Logs)-max(10, m.LogView.Height))
	logContent := strings.Join(m.Logs[start:], "\n")
	m.LogView.SetContent(logContent)
	m.LogView.GotoBottom()
}

// ---------- Commands ----------

func (m Model) startLoadTest() tea.Cmd {
	return func() tea.Msg {
		go runLoadTest(m.Config, m.Metrics, m.msgChan, m.TotalRequests)
		return nil
	}
}

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		select {
		case msg := <-m.msgChan:
			return msg
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	}
}

// ---------- Small helpers (local) ----------

func renderHistogram(labels []string, get func(i int) uint64, total uint64, width, height int) string {
	if width < 20 {
		width = 20
	}
	if height < 8 {
		height = 8
	}
	if total == 0 {
		return styleMuted.Render("No data yet.")
	}

	labelW := 8
	for _, l := range labels {
		if len(l) > labelW {
			labelW = len(l)
		}
	}
	labelW = clamp(labelW, 6, 12)

	barW := width - labelW - 12 // space for " 123 (12.3%)"
	if barW < 10 {
		barW = 10
	}

	var maxV uint64
	for i := range labels {
		v := get(i)
		if v > maxV {
			maxV = v
		}
	}
	if maxV == 0 {
		return styleMuted.Render("No latency samples.")
	}

	lines := make([]string, 0, len(labels))
	for i, label := range labels {
		v := get(i)
		pct := (float64(v) / float64(total)) * 100.0

		fill := int(math.Round(float64(v) / float64(maxV) * float64(barW)))
		if fill < 0 {
			fill = 0
		}
		if fill > barW {
			fill = barW
		}

		bar := strings.Repeat("█", fill) + strings.Repeat(" ", barW-fill)
		line := fmt.Sprintf("%-*s %s %6d (%5.1f%%)", labelW, label, bar, v, pct)
		lines = append(lines, line)
	}

	// Fit to available height
	if len(lines) > height {
		lines = lines[:height]
	}

	return strings.Join(lines, "\n")
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
