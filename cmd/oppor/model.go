// cmd/oppor/model.go
package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Color Palette & Styles ---

var (
	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	warning   = lipgloss.AdaptiveColor{Light: "#F25D94", Dark: "#F55385"}
	text      = lipgloss.AdaptiveColor{Light: "#333333", Dark: "#EEEEEE"}

	// Gradients for latency
	gradGreen  = lipgloss.Color("#04B575")
	gradYellow = lipgloss.Color("#FFFF00")
	gradRed    = lipgloss.Color("#FF0000")

	styleBase = lipgloss.NewStyle().
			Foreground(text)

	styleBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(highlight).
			Padding(0, 1)

	styleTitle = lipgloss.NewStyle().
			Foreground(special).
			Bold(true).
			Padding(0, 1).
			Background(lipgloss.Color("#1a1a1a")).
			MarginBottom(1)

	styleStatBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(subtle).
			Padding(0, 1).
			Width(22)

	styleStatLabel = lipgloss.NewStyle().
			Foreground(subtle).
			Faint(true)

	styleStatValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(text).
			Padding(1, 0, 0, 0) // Fixed: Capitalized Padding
)

type Model struct {
	Config    Config
	Metrics   *Metrics
	Running   bool
	StartTime time.Time

	// UI Components
	Progress progress.Model
	Spinner  spinner.Model
	LogView  viewport.Model

	// Data
	Logs       []string
	LastUpdate time.Time
	Width      int
	Height     int

	// Control
	Quit          bool
	AgberoMetrics map[string]interface{}

	// Progress tracking
	TotalRequests     uint64
	CompletedRequests uint64

	msgChan chan tea.Msg
}

func NewModel(cfg Config) Model {
	// Styled Progress Bar
	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
		progress.WithoutPercentage(),
	)

	// Styled Spinner
	spin := spinner.New()
	spin.Spinner = spinner.Pulse
	spin.Style = lipgloss.NewStyle().Foreground(special)

	// Logs Viewport
	logView := viewport.New(80, 10)
	logView.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#a0a0a0"))

	return Model{
		Config:        cfg,
		Metrics:       &Metrics{},
		Running:       true,
		StartTime:     time.Now(),
		Progress:      prog,
		Spinner:       spin,
		LogView:       logView,
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
		updateMetricsAfter(100*time.Millisecond),
		fetchAgberoMetrics(m.Config.MetricsURL),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := []tea.Cmd{m.listenForMessages()}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.Quit = true
			return m, tea.Quit
		case "up", "k":
			m.LogView.LineUp(1)
		case "down", "j":
			m.LogView.LineDown(1)
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.LogView.Width = msg.Width - 6
		m.Progress.Width = msg.Width - 10

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.Spinner, cmd = m.Spinner.Update(msg)
		cmds = append(cmds, cmd)

	case progressMsg:
		m.CompletedRequests = msg.completed
		if msg.total > 0 {
			m.Progress.SetPercent(float64(msg.completed) / float64(msg.total))
		}
		if msg.done {
			m.Running = false
			m.Progress.SetPercent(1.0)
		}

	case metricsMsg:
		m.LastUpdate = time.Now()
		snap := m.Metrics.Snapshot()
		// Auto-stop checks
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
		if m.Running {
			cmds = append(cmds, updateMetricsAfter(250*time.Millisecond))
		}

	case logMsg:
		// Colorize log line based on method and status
		styledLog := styleLogLine(msg.text)
		m.Logs = append(m.Logs, styledLog)
		if len(m.Logs) > 300 {
			m.Logs = m.Logs[len(m.Logs)-300:]
		}
		m.updateLogView()

	case agberoMetricsMsg:
		m.AgberoMetrics = msg.metrics
		if m.Config.MetricsURL != "" {
			cmds = append(cmds, tea.Tick(5*time.Second, func(time.Time) tea.Msg {
				return fetchAgberoMetrics(m.Config.MetricsURL)()
			}))
		}
	}

	var cmd tea.Cmd
	m.LogView, cmd = m.LogView.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m Model) View() string {
	if m.Width == 0 {
		return "Initializing UI..."
	}

	snap := m.Metrics.Snapshot()

	// 1. Header Section
	header := m.renderHeader(snap)

	// 2. Stats Grid (Hero Stats)
	stats := m.renderHeroStats(snap)

	// 3. Middle Section: Latency Graph & Codes
	middleHeight := 10 // Fixed height for graph area
	middle := m.renderMiddleSection(snap, middleHeight)

	// 4. Logs Section (Fill remaining height)
	usedHeight := lipgloss.Height(header) + lipgloss.Height(stats) + lipgloss.Height(middle) + 4
	logHeight := m.Height - usedHeight
	if logHeight < 5 {
		logHeight = 5
	}
	m.LogView.Height = logHeight

	// Fixed: Manually render title inside the border since BorderLabel doesn't exist
	logTitle := styleTitle.Render(" Real-time Logs ")
	logs := styleBorder.
		Width(m.Width - 2).
		Render(lipgloss.JoinVertical(lipgloss.Left, logTitle, m.LogView.View()))

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		stats,
		middle,
		logs,
	)
}

// --- Render Helpers ---

func (m Model) renderHeader(snap MetricsSnapshot) string {
	var status string
	if m.Running {
		status = fmt.Sprintf("%s RUNNING", m.Spinner.View())
	} else {
		status = "✔ DONE"
	}

	target := "-"
	if len(m.Config.Targets) > 0 {
		target = m.Config.Targets[0]
		if len(m.Config.Targets) > 1 {
			target += fmt.Sprintf(" (+%d)", len(m.Config.Targets)-1)
		}
	}
	// Truncate target if too long
	if len(target) > 30 {
		target = target[:27] + "..."
	}

	elapsed := time.Since(m.StartTime).Round(time.Second).String()

	// Progress Bar Section
	var progStr string
	if m.Config.Requests > 0 {
		progStr = fmt.Sprintf(" %s %d/%d", m.Progress.View(), m.CompletedRequests, m.TotalRequests)
	} else if m.Config.Duration > 0 {
		remain := m.Config.Duration - time.Since(m.StartTime)
		if remain < 0 {
			remain = 0
		}
		progStr = fmt.Sprintf(" Time Remaining: %s", remain.Round(time.Second))
	} else {
		progStr = " Infinite Run (Ctrl+C to stop)"
	}

	left := lipgloss.JoinVertical(lipgloss.Left,
		styleTitle.MarginBottom(0).Render(" OPPOЯ "),
		lipgloss.NewStyle().PaddingLeft(1).Foreground(subtle).Render(target),
	)

	right := lipgloss.JoinVertical(lipgloss.Right,
		lipgloss.NewStyle().Bold(true).Foreground(highlight).Render(status),
		lipgloss.NewStyle().Foreground(subtle).Render(elapsed),
	)

	topBar := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(m.Width/2).Align(lipgloss.Left).Render(left),
		lipgloss.NewStyle().Width(m.Width/2-4).Align(lipgloss.Right).Render(right),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		topBar,
		lipgloss.NewStyle().Padding(1, 0).Render(progStr),
	)
}

func (m Model) renderHeroStats(snap MetricsSnapshot) string {
	// Calc dynamic RPS
	rps := snap.RequestsPerSec
	if rps == 0 && snap.TotalRequests > 0 {
		dur := time.Since(m.StartTime).Seconds()
		if dur > 0 {
			rps = uint64(float64(snap.TotalRequests) / dur)
		}
	}

	// Format large numbers
	formatNum := func(n uint64) string {
		if n >= 1_000_000 {
			return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
		} else if n >= 1_000 {
			return fmt.Sprintf("%.1fK", float64(n)/1_000)
		}
		return fmt.Sprintf("%d", n)
	}

	boxTotal := renderStatBox("TOTAL REQ", formatNum(snap.TotalRequests), "")
	boxRPS := renderStatBox("RPS", fmt.Sprintf("%d", rps), "")
	boxSucc := renderStatBox("SUCCESS %", fmt.Sprintf("%.1f%%", snap.SuccessRate), getSuccessColor(snap.SuccessRate))
	boxLat := renderStatBox("AVG LATENCY", fmt.Sprintf("%.1f ms", snap.AvgLatencyMs), getLatencyColor(snap.AvgLatencyMs))

	// Create a responsive grid
	availWidth := m.Width - 4
	// Allow boxes to shrink slightly if needed, or wrap
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		boxTotal, boxRPS, boxSucc, boxLat,
	)

	return lipgloss.NewStyle().Padding(0, 1, 1, 1).MaxWidth(availWidth).Render(row)
}

func renderStatBox(label, value, colorHex string) string {
	valStyle := styleStatValue.Copy()
	if colorHex != "" {
		valStyle = valStyle.Foreground(lipgloss.Color(colorHex))
	}

	return styleStatBox.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			styleStatLabel.Render(label),
			valStyle.Render(value),
		),
	)
}

func (m Model) renderMiddleSection(snap MetricsSnapshot, h int) string {
	// Left: Latency Histogram
	// Right: Status Codes & Agbero Info

	halfWidth := (m.Width / 2) - 4
	if halfWidth < 30 {
		halfWidth = 30
	}

	// --- Histogram ---
	labels := []string{"<10ms", "50ms", "100ms", "250ms", "500ms", "1s", ">1s"}

	// Map metrics buckets to these labels
	counts := []uint64{
		m.Metrics.LatencyBuckets[0].Load(), // <10
		m.Metrics.LatencyBuckets[1].Load(), // 10-50
		m.Metrics.LatencyBuckets[2].Load(), // 50-100
		m.Metrics.LatencyBuckets[3].Load(), // 100-250
		m.Metrics.LatencyBuckets[4].Load(), // 250-500
		m.Metrics.LatencyBuckets[5].Load(), // 500-1000
	}
	// Sum remaining buckets for >1s
	var slow uint64
	for i := 6; i < 10; i++ {
		slow += m.Metrics.LatencyBuckets[i].Load()
	}
	counts = append(counts, slow)

	hist := renderVisualHistogram(labels, counts, snap.TotalRequests, halfWidth)

	// Fixed: Manual title inside border
	histTitle := styleTitle.Render(" Latency Dist. ")
	histBox := styleBorder.Width(halfWidth).Height(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, histTitle, hist),
	)

	// --- Status Codes & Details ---

	// Status Code Grid
	statusContent := lipgloss.JoinVertical(lipgloss.Left,
		fmt.Sprintf("%s %d", styleBase.Foreground(gradGreen).Render("2xx OK:   "), snap.StatusCode2xx),
		fmt.Sprintf("%s %d", styleBase.Foreground(lipgloss.Color("#5fafff")).Render("3xx Redir:"), snap.StatusCode3xx),
		fmt.Sprintf("%s %d", styleBase.Foreground(warning).Render("4xx User: "), snap.StatusCode4xx),
		fmt.Sprintf("%s %d", styleBase.Foreground(gradRed).Render("5xx Err:  "), snap.StatusCode5xx),
		"",
		fmt.Sprintf("Active Conns: %d", snap.ActiveConnections),
		fmt.Sprintf("Throughput:   %.1f MB/s", snap.ThroughputMBps),
	)

	// Add Agbero context if available
	if m.AgberoMetrics != nil {
		statusContent += "\n\n" + styleStatLabel.Render("-- Agbero Proxy --")
		statusContent += "\n" + m.renderAgberoSummary(halfWidth-4)
	}

	// Fixed: Manual title inside border
	statusTitle := styleTitle.Render(" Details ")
	statusBox := styleBorder.Width(halfWidth).Height(h).Render(
		lipgloss.JoinVertical(lipgloss.Left, statusTitle, statusContent),
	)

	return lipgloss.JoinHorizontal(lipgloss.Top, histBox, statusBox)
}

func renderVisualHistogram(labels []string, counts []uint64, total uint64, width int) string {
	if total == 0 {
		return "Waiting for data..."
	}

	var maxVal uint64
	for _, c := range counts {
		if c > maxVal {
			maxVal = c
		}
	}
	if maxVal == 0 {
		return "No latency data"
	}

	// Effective bar width (width - label width - percentage width)
	labelW := 7
	percentW := 6
	barW := width - labelW - percentW - 4
	if barW < 5 {
		barW = 5
	}

	var s strings.Builder
	for i, count := range counts {
		if i >= len(labels) {
			break
		}

		pct := 0.0
		if total > 0 {
			pct = (float64(count) / float64(total)) * 100
		}

		// Determine bar color based on index (higher index = slower = redder)
		barColor := gradGreen
		if i > 2 {
			barColor = gradYellow
		}
		if i > 4 {
			barColor = gradRed
		}

		barLen := int(math.Round(float64(count) / float64(maxVal) * float64(barW)))
		barChar := "▇"

		barStr := lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat(barChar, barLen))
		emptyStr := strings.Repeat(" ", barW-barLen)

		line := fmt.Sprintf("%-*s %s%s %5.1f%%",
			labelW, labels[i],
			barStr, emptyStr,
			pct,
		)
		s.WriteString(line + "\n")
	}
	return s.String()
}

// --- Logic Helpers ---

func (m *Model) updateLogView() {
	if len(m.Logs) == 0 {
		return
	}
	content := strings.Join(m.Logs, "\n")
	m.LogView.SetContent(content)
	m.LogView.GotoBottom()
}

func (m Model) startLoadTest() tea.Cmd {
	return func() tea.Msg {
		go runLoadTest(m.Config, m.Metrics, m.msgChan, m.TotalRequests)
		return nil
	}
}

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		return <-m.msgChan
	}
}

func (m Model) renderAgberoSummary(w int) string {
	hosts, ok := m.AgberoMetrics["hosts"].(map[string]interface{})
	if !ok || len(hosts) == 0 {
		return "No host data"
	}

	type row struct {
		h    string
		reqs float64
	}
	var rows []row
	for k, v := range hosts {
		if data, ok := v.(map[string]interface{}); ok {
			if r, ok := data["total_reqs"].(float64); ok {
				rows = append(rows, row{k, r})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].reqs > rows[j].reqs })

	if len(rows) > 3 {
		rows = rows[:3]
	}

	var out strings.Builder
	for _, r := range rows {
		out.WriteString(fmt.Sprintf("• %s: %.0f\n", r.h, r.reqs))
	}
	return out.String()
}

// --- Styling Helpers ---

func getSuccessColor(rate float64) string {
	if rate >= 99.0 {
		return "#04B575"
	} // Green
	if rate >= 95.0 {
		return "#FFFF00"
	} // Yellow
	return "#FF0000" // Red
}

func getLatencyColor(ms float64) string {
	if ms < 100 {
		return "#04B575"
	}
	if ms < 500 {
		return "#FFFF00"
	}
	return "#FF0000"
}

func styleLogLine(line string) string {
	// Basic syntax highlighting for logs
	if strings.Contains(line, " 200 ") {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#55aa55")).Render(line)
	}
	if strings.Contains(line, " 500 ") || strings.Contains(line, " 502 ") {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5555")).Render(line)
	}
	if strings.Contains(line, "GET") {
		return strings.Replace(line, "GET", lipgloss.NewStyle().Foreground(lipgloss.Color("#5fafff")).Bold(true).Render("GET"), 1)
	}
	if strings.Contains(line, "POST") {
		return strings.Replace(line, "POST", lipgloss.NewStyle().Foreground(lipgloss.Color("#ffaf00")).Bold(true).Render("POST"), 1)
	}
	return line
}
