// cmd/oppor/model.go
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Constants & Styles ---
var (
	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}
	text      = lipgloss.AdaptiveColor{Light: "#333333", Dark: "#EEEEEE"}

	// Gradients
	gradGreen  = lipgloss.Color("#04B575")
	gradYellow = lipgloss.Color("#FFFF00")
	gradRed    = lipgloss.Color("#FF0000")
	warning    = lipgloss.Color("#FF0000")

	// --- Layout Styles ---
	styleBase = lipgloss.NewStyle().Foreground(text)

	styleControlBar = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(subtle).
			Padding(0, 1, 1, 1).
			MarginBottom(1)

	styleInput = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtle).
			Padding(0, 1).
			MarginRight(1)

	styleInputFocused = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(highlight).
				Padding(0, 1).
				MarginRight(1)

	styleBtnStart = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#04B575")).
			Bold(true).
			Padding(0, 2).
			MarginLeft(1)

	styleBtnStop = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF0000")).
			Bold(true).
			Padding(0, 2).
			MarginLeft(1)

	styleBtnInactive = lipgloss.NewStyle().
				Foreground(subtle).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(subtle).
				Padding(0, 1).
				MarginLeft(1)

	// Dashboard Styles
	styleStatBox = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(subtle).
			Padding(0, 1).
			Width(20)

	styleStatLabel = lipgloss.NewStyle().Foreground(subtle).Faint(true)
	styleStatValue = lipgloss.NewStyle().Bold(true).Foreground(text)

	styleLogBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(subtle).
			Padding(0, 1)
)

// Input Indices
const (
	InputTarget = iota
	InputConcurrency
	InputRequests
	InputDuration
	InputBtn // Virtual index for the button
)

type Model struct {
	Config  Config
	Metrics *Metrics

	// State
	Running   bool
	StartTime time.Time
	EndTime   time.Time

	// UI Components - Inputs
	Inputs     []textinput.Model
	FocusIndex int

	// UI Components - Dashboard
	Progress progress.Model
	Spinner  spinner.Model
	LogView  viewport.Model

	// Data
	Logs   []string
	Width  int
	Height int

	// Logic
	WorkerPool    *Pool
	AgberoMetrics map[string]interface{}
	msgChan       chan tea.Msg
}

func NewModel(cfg Config) Model {
	// Initialize Inputs
	inputs := make([]textinput.Model, 4)

	// 1. URL
	inputs[InputTarget] = textinput.New()
	inputs[InputTarget].Placeholder = "http://localhost:8080"
	inputs[InputTarget].Focus() // Default focus
	inputs[InputTarget].Width = 40
	if len(cfg.Targets) > 0 {
		inputs[InputTarget].SetValue(cfg.Targets[0])
	}

	// 2. Concurrency
	inputs[InputConcurrency] = textinput.New()
	inputs[InputConcurrency].Placeholder = "10"
	inputs[InputConcurrency].Width = 6
	inputs[InputConcurrency].SetValue(strconv.Itoa(cfg.Concurrency))

	// 3. Requests
	inputs[InputRequests] = textinput.New()
	inputs[InputRequests].Placeholder = "∞"
	inputs[InputRequests].Width = 8
	if cfg.Requests > 0 {
		inputs[InputRequests].SetValue(strconv.Itoa(cfg.Requests))
	}

	// 4. Duration
	inputs[InputDuration] = textinput.New()
	inputs[InputDuration].Placeholder = "∞"
	inputs[InputDuration].Width = 8
	if cfg.Duration > 0 {
		inputs[InputDuration].SetValue(cfg.Duration.String())
	}

	// Dashboard
	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithoutPercentage(),
	)

	spin := spinner.New()
	spin.Spinner = spinner.Pulse
	spin.Style = lipgloss.NewStyle().Foreground(special)

	logView := viewport.New(80, 10)
	logView.SetContent("Ready to test. Enter URL above and press Run.")

	return Model{
		Config:     cfg,
		Metrics:    &Metrics{},
		Inputs:     inputs,
		FocusIndex: InputTarget,
		Progress:   prog,
		Spinner:    spin,
		LogView:    logView,
		Logs:       []string{},
		msgChan:    make(chan tea.Msg, 1000),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.listenForMessages(),
	)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.WorkerPool != nil {
				m.WorkerPool.Stop()
			}
			return m, tea.Quit

		case "tab", "shift+tab":
			// Cycle Focus
			direction := 1
			if msg.String() == "shift+tab" {
				direction = -1
			}

			// Handle inputs blur
			if m.FocusIndex < len(m.Inputs) {
				m.Inputs[m.FocusIndex].Blur()
			}

			m.FocusIndex += direction

			// Wrap around (Inputs + 1 Button)
			maxIndex := len(m.Inputs) // 4 inputs + 1 button = 0..4
			if m.FocusIndex > maxIndex {
				m.FocusIndex = 0
			}
			if m.FocusIndex < 0 {
				m.FocusIndex = maxIndex
			}

			// Handle inputs focus
			if m.FocusIndex < len(m.Inputs) {
				cmds = append(cmds, m.Inputs[m.FocusIndex].Focus())
			}
			return m, tea.Batch(cmds...)

		case "enter":
			// If on button, toggle run
			if m.FocusIndex == InputBtn {
				return m.toggleRun()
			}
			// If inside input, enter usually means "Next" or "Run"
			// Let's make Enter on URL trigger Run for speed
			if m.FocusIndex == InputTarget {
				return m.toggleRun()
			}
			// Otherwise move focus next
			m.Inputs[m.FocusIndex].Blur()
			m.FocusIndex++
			if m.FocusIndex < len(m.Inputs) {
				cmds = append(cmds, m.Inputs[m.FocusIndex].Focus())
			}
			return m, tea.Batch(cmds...)
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.LogView.Width = msg.Width - 6
		m.Progress.Width = msg.Width - 10

	// --- Worker Messages ---
	case spinner.TickMsg:
		if m.Running {
			var cmd tea.Cmd
			m.Spinner, cmd = m.Spinner.Update(msg)
			cmds = append(cmds, cmd)
		}

	case progressMsg:
		if msg.total > 0 {
			m.Progress.SetPercent(float64(msg.completed) / float64(msg.total))
		}
		if msg.done && m.Running {
			m.stopTest()
		}

	case metricsMsg:
		// Auto-stop logic based on duration/requests logic handled in worker_pool
		// Here we just refresh
		if !m.Running {
			// If metrics arrive late, just ignore or update final snapshot
		}

	case logMsg:
		m.Logs = append(m.Logs, styleLogLine(msg.text))
		if len(m.Logs) > 300 {
			m.Logs = m.Logs[len(m.Logs)-300:]
		}
		m.updateLogView()
	}

	// Update Focused Input
	if m.FocusIndex < len(m.Inputs) {
		var cmd tea.Cmd
		m.Inputs[m.FocusIndex], cmd = m.Inputs[m.FocusIndex].Update(msg)
		cmds = append(cmds, cmd)
	}

	// Keep log view scrollable
	var cmd tea.Cmd
	m.LogView, cmd = m.LogView.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// --- Logic ---

func (m *Model) toggleRun() (tea.Model, tea.Cmd) {
	if m.Running {
		m.stopTest()
		return m, nil
	}
	return m.startTest()
}

func (m *Model) startTest() (tea.Model, tea.Cmd) {
	// 1. Read Config from Inputs
	m.Config.Targets = []string{m.Inputs[InputTarget].Value()}

	if c, err := strconv.Atoi(m.Inputs[InputConcurrency].Value()); err == nil && c > 0 {
		m.Config.Concurrency = c
	}
	if r, err := strconv.Atoi(m.Inputs[InputRequests].Value()); err == nil {
		m.Config.Requests = r
	}
	if d, err := time.ParseDuration(m.Inputs[InputDuration].Value()); err == nil {
		m.Config.Duration = d
	} else {
		m.Config.Duration = 0
	}

	// 2. Reset UI State
	m.Running = true
	m.StartTime = time.Now()
	m.EndTime = time.Time{}
	m.Metrics = &Metrics{} // Zero metrics
	m.Logs = []string{}
	m.updateLogView()
	m.Progress.SetPercent(0)

	// 3. Start Worker
	m.WorkerPool = NewWorkerPool(m.Config, m.Metrics, m.msgChan, uint64(m.Config.Requests))
	return m, func() tea.Msg {
		go m.WorkerPool.Start()
		return nil
	}
}

func (m *Model) stopTest() {
	m.Running = false
	m.EndTime = time.Now()
	if m.WorkerPool != nil {
		m.WorkerPool.Stop()
	}
	m.Progress.SetPercent(1.0)
}

func (m *Model) listenForMessages() tea.Cmd {
	return func() tea.Msg {
		return <-m.msgChan
	}
}

func (m *Model) updateLogView() {
	if len(m.Logs) == 0 {
		m.LogView.SetContent("")
		return
	}
	m.LogView.SetContent(strings.Join(m.Logs, "\n"))
	m.LogView.GotoBottom()
}

// --- View ---

func (m Model) View() string {
	if m.Width == 0 {
		return "loading..."
	}

	// 1. Control Bar (Top)
	controls := m.renderControls()

	// 2. Dashboard (Bottom)
	dashboard := m.renderDashboard()

	return lipgloss.JoinVertical(lipgloss.Left, controls, dashboard)
}

func (m Model) renderControls() string {
	// Helper to render input with label
	renderInput := func(i int, label string) string {
		style := styleInput
		if m.FocusIndex == i {
			style = styleInputFocused
		}

		return lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Foreground(subtle).Faint(true).MarginLeft(1).Render(label),
			style.Render(m.Inputs[i].View()),
		)
	}

	// Button Logic
	var btn string
	if m.Running {
		btn = styleBtnStop.Render("■ STOP")
	} else {
		btn = styleBtnStart.Render("▶ RUN")
	}
	// Focus highlight for button
	if m.FocusIndex == InputBtn {
		btn = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(highlight).Render(btn)
	} else {
		btn = lipgloss.NewStyle().Border(lipgloss.RoundedBorder(), false).Padding(1).Render(btn) // spacing padding
	}

	// Row 1: Method + URL + Button
	method := lipgloss.NewStyle().Foreground(lipgloss.Color("#ffaf00")).Bold(true).Padding(1, 1, 0, 0).Render(m.Config.Method)
	row1 := lipgloss.JoinHorizontal(lipgloss.Bottom,
		method,
		renderInput(InputTarget, "Target URL"),
		btn,
	)

	// Row 2: Settings
	row2 := lipgloss.JoinHorizontal(lipgloss.Top,
		renderInput(InputConcurrency, "Workers"),
		renderInput(InputRequests, "Requests"),
		renderInput(InputDuration, "Duration"),
	)

	return styleControlBar.Width(m.Width).Render(
		lipgloss.JoinVertical(lipgloss.Left, row1, row2),
	)
}

func (m Model) renderDashboard() string {
	snap := m.Metrics.Snapshot()

	// 1. Stats Row
	stats := m.renderHeroStats(snap)

	// 2. Main Visuals
	middle := m.renderMiddleSection(snap)

	// 3. Logs
	// Dynamic Height Calculation
	controlsHeight := 8 // Approx height of top bar
	statsHeight := lipgloss.Height(stats)
	midHeight := lipgloss.Height(middle)

	availHeight := m.Height - controlsHeight - statsHeight - midHeight - 2
	if availHeight < 5 {
		availHeight = 5
	}
	m.LogView.Height = availHeight

	logs := styleLogBox.Width(m.Width - 2).Render(m.LogView.View())

	return lipgloss.JoinVertical(lipgloss.Left,
		stats,
		middle,
		logs,
	)
}

// Reuse existing render helpers
func (m Model) renderHeroStats(snap MetricsSnapshot) string {
	// Freeze Logic
	dur := time.Since(m.StartTime).Seconds()
	if !m.Running && !m.EndTime.IsZero() {
		dur = m.EndTime.Sub(m.StartTime).Seconds()
	} else if !m.Running {
		dur = 0
	}

	rps := snap.RequestsPerSec
	if !m.Running && snap.TotalRequests > 0 && dur > 0 {
		rps = uint64(float64(snap.TotalRequests) / dur)
	}

	// Formatters
	formatNum := func(n uint64) string {
		if n >= 1_000_000 {
			return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
		}
		if n >= 1_000 {
			return fmt.Sprintf("%.1fK", float64(n)/1_000)
		}
		return fmt.Sprintf("%d", n)
	}

	boxTotal := renderStatBox("REQS", formatNum(snap.TotalRequests), "")
	boxRPS := renderStatBox("RPS", fmt.Sprintf("%d", rps), "")
	boxSucc := renderStatBox("SUCCESS", fmt.Sprintf("%.1f%%", snap.SuccessRate), getSuccessColor(snap.SuccessRate))
	boxLat := renderStatBox("LATENCY", fmt.Sprintf("%.0f ms", snap.AvgLatencyMs), getLatencyColor(snap.AvgLatencyMs))

	// Status Label
	var statusLbl string
	if m.Running {
		statusLbl = lipgloss.NewStyle().Foreground(highlight).Render(fmt.Sprintf("%s TESTING...", m.Spinner.View()))
	} else {
		statusLbl = lipgloss.NewStyle().Foreground(subtle).Render("IDLE")
	}

	// Layout
	boxes := lipgloss.JoinHorizontal(lipgloss.Top, boxTotal, boxRPS, boxSucc, boxLat)

	// Add Progress Bar if running
	if m.Running {
		return lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Padding(0, 1).Render(boxes),
			lipgloss.NewStyle().Padding(0, 2).Render(statusLbl+" "+m.Progress.View()),
		)
	}

	return lipgloss.NewStyle().Padding(0, 1).Render(boxes)
}

func renderStatBox(label, value, colorHex string) string {
	s := styleStatValue.Copy()
	if colorHex != "" {
		s = s.Foreground(lipgloss.Color(colorHex))
	}
	return styleStatBox.Render(lipgloss.JoinVertical(lipgloss.Left, styleStatLabel.Render(label), s.Render(value)))
}

func (m Model) renderMiddleSection(snap MetricsSnapshot) string {
	// Histogram
	labels := []string{"<10ms", "50ms", "100ms", "500ms", "1s", ">1s"}
	counts := []uint64{
		m.Metrics.LatencyBuckets[0].Load(),
		m.Metrics.LatencyBuckets[1].Load(),
		m.Metrics.LatencyBuckets[2].Load(),
		m.Metrics.LatencyBuckets[4].Load(),
		m.Metrics.LatencyBuckets[5].Load(),
	}
	var slow uint64
	for i := 6; i < 10; i++ {
		slow += m.Metrics.LatencyBuckets[i].Load()
	}
	counts = append(counts, slow)

	hist := renderVisualHistogram(labels, counts, snap.TotalRequests, 40)

	// Codes
	codes := lipgloss.JoinVertical(lipgloss.Left,
		lipgloss.NewStyle().Bold(true).Underline(true).Render("Status Codes"),
		fmt.Sprintf("%s %d", styleBase.Foreground(gradGreen).Render("2xx:"), snap.StatusCode2xx),
		fmt.Sprintf("%s %d", styleBase.Foreground(warning).Render("4xx:"), snap.StatusCode4xx),
		fmt.Sprintf("%s %d", styleBase.Foreground(gradRed).Render("5xx:"), snap.StatusCode5xx),
	)

	return lipgloss.NewStyle().Padding(1, 2).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, hist, lipgloss.NewStyle().MarginLeft(4).Render(codes)),
	)
}

func renderVisualHistogram(labels []string, counts []uint64, total uint64, width int) string {
	var maxVal uint64
	for _, c := range counts {
		if c > maxVal {
			maxVal = c
		}
	}

	var s strings.Builder
	for i, count := range counts {
		if i >= len(labels) {
			break
		}
		barLen := 0
		if maxVal > 0 {
			barLen = int((float64(count) / float64(maxVal)) * float64(width))
		}

		barColor := gradGreen
		if i > 2 {
			barColor = gradYellow
		}
		if i > 4 {
			barColor = gradRed
		}

		s.WriteString(fmt.Sprintf("%6s | %s %d\n",
			labels[i],
			lipgloss.NewStyle().Foreground(barColor).Render(strings.Repeat("█", barLen)),
			count,
		))
	}
	return s.String()
}

// Styling Helpers
func getSuccessColor(rate float64) string {
	if rate >= 99.0 {
		return "#04B575"
	}
	if rate >= 95.0 {
		return "#FFFF00"
	}
	return "#FF0000"
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
	if strings.Contains(line, " 200 ") {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#55aa55")).Render(line)
	}
	if strings.Contains(line, " 500 ") || strings.Contains(line, " 502 ") {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff5555")).Render(line)
	}
	if strings.Contains(line, "ERROR") {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#ff0000")).Bold(true).Render(line)
	}
	return line
}
