package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Styles ---

var (
	pColor = lipgloss.Color("#FF6C37") // Brand Orange
	sColor = lipgloss.Color("#262626") // Surface Dark
	bColor = lipgloss.Color("#121212") // Background Black
	tColor = lipgloss.Color("#A3A3A3") // Text Muted
	wColor = lipgloss.Color("#FFFFFF") // White

	// Layout Containers
	appStyle = lipgloss.NewStyle().Background(bColor).Foreground(wColor)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#404040")).
			Padding(0, 1)

	// Header
	headerStyle = lipgloss.NewStyle().
			Background(sColor).
			Foreground(wColor).
			Padding(0, 1).
			Bold(true)

	// Inputs
	labelStyle = lipgloss.NewStyle().Foreground(tColor).Bold(true).MarginRight(1)

	inputStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#404040")).
			Padding(0, 1)

	focusStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(pColor).
			Padding(0, 1)

	// Stats Cards
	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(lipgloss.Color("#404040")).
			Padding(0, 2)

	cardLabelStyle = lipgloss.NewStyle().Foreground(tColor).Width(12)
	cardValueStyle = lipgloss.NewStyle().Foreground(wColor).Bold(true)

	// Tabs
	tabStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(lipgloss.Color("#404040")).
			Padding(0, 2)

	activeTabStyle = tabStyle.Copy().
			BorderForeground(pColor).
			Foreground(pColor).
			Bold(true)

	// Logs
	logTimeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#555")).MarginRight(1)
	logInfoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#34D399"))
	logErrStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
)

// --- Keys ---

type keyMap struct {
	Run      key.Binding
	Stop     key.Binding
	Quit     key.Binding
	Cycle    key.Binding
	Back     key.Binding
	Logs     key.Binding
	Metrics  key.Binding
	Histo    key.Binding
	Clear    key.Binding // Esc to clear focus
	PageUp   key.Binding
	PageDown key.Binding
}

var keys = keyMap{
	Run:      key.NewBinding(key.WithKeys("enter", "ctrl+r"), key.WithHelp("enter", "run/next")),
	Stop:     key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "stop")),
	Quit:     key.NewBinding(key.WithKeys("ctrl+q"), key.WithHelp("ctrl+q", "quit")),
	Cycle:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next field")),
	Back:     key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("sh+tab", "prev field")),
	Logs:     key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "logs")),
	Metrics:  key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "metrics")),
	Histo:    key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "histogram")),
	Clear:    key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "unfocus")),
	PageUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "scroll up")),
	PageDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "scroll down")),
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Run, k.Stop, k.Cycle, k.Clear, k.Quit}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{k.ShortHelp()}
}

// --- Enums ---

const (
	InputMethod = iota
	InputURL
	InputConcurrency
	InputRequests
	InputDuration
	InputRate
	InputHeaders
	InputBody
	inputCount
)

const (
	ViewLogs = iota
	ViewMetrics
	ViewHistogram
)

// --- Model ---

type Ui struct {
	Config  Config
	Metrics *Metrics

	// Enabled
	Running   bool
	StartTime time.Time
	Logs      []string

	// Layout
	Width, Height int
	ActiveView    int
	FocusIndex    int // -1 means no input focused

	// Components
	Inputs      []textinput.Model
	Spinner     spinner.Model
	ProgressBar progress.Model
	Viewport    viewport.Model
	Help        help.Model

	// Internal
	WorkerPool *Pool
	msgChan    chan tea.Msg
}

func NewModel(cfg Config) Ui {
	inputs := make([]textinput.Model, inputCount)

	for i := range inputs {
		t := textinput.New()
		t.Cursor.Style = lipgloss.NewStyle().Foreground(pColor)

		switch i {
		case InputMethod:
			t.SetValue("GET")
			t.Placeholder = "GET"
			t.CharLimit = 7
		case InputURL:
			t.Placeholder = "http://localhost:8080"
			if len(cfg.Targets) > 0 {
				t.SetValue(cfg.Targets[0])
			}
		case InputConcurrency:
			t.SetValue("10")
			t.Placeholder = "10"
			t.CharLimit = 5
		case InputRequests:
			t.SetValue("0")
			t.Placeholder = "Inf"
			t.CharLimit = 8
		case InputDuration:
			t.SetValue("10s")
			t.Placeholder = "10s"
			t.CharLimit = 8
		case InputRate:
			t.SetValue("0")
			t.Placeholder = "No Limit"
			t.CharLimit = 8
		case InputHeaders:
			t.Placeholder = "Key: Val, Key2: Val2"
		case InputBody:
			t.Placeholder = `{"json": "payload"}`
		}
		inputs[i] = t
	}

	// Start with URL focused
	inputs[InputURL].Focus()

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(pColor)

	vp := viewport.New(0, 0)

	return Ui{
		Config:      cfg,
		Metrics:     &Metrics{},
		Inputs:      inputs,
		FocusIndex:  InputURL,
		Spinner:     s,
		ProgressBar: progress.New(progress.WithDefaultGradient()),
		Viewport:    vp,
		Help:        help.New(),
		msgChan:     make(chan tea.Msg, 1000),
		ActiveView:  ViewLogs,
		Logs:        []string{},
	}
}

func (m Ui) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.Spinner.Tick,
		m.waitForMsg(),
	)
}

func (m *Ui) waitForMsg() tea.Cmd {
	return func() tea.Msg { return <-m.msgChan }
}

func (m Ui) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.resizeComponents()

	case tea.KeyMsg:
		// 1. Global High Priority
		switch {
		case key.Matches(msg, keys.Stop):
			if m.Running {
				m.stopTest()
				return m, nil
			}
			return m, tea.Quit

		case key.Matches(msg, keys.Quit):
			if m.Running {
				m.stopTest()
			}
			return m, tea.Quit

		case key.Matches(msg, keys.Clear):
			m.FocusIndex = -1
			for i := range m.Inputs {
				m.Inputs[i].Blur()
			}
			return m, nil

		case key.Matches(msg, keys.Cycle):
			m.cycleFocus(1)
			return m, nil

		case key.Matches(msg, keys.Back):
			m.cycleFocus(-1)
			return m, nil
		}

		// 2. Input Handling (If focused)
		if m.FocusIndex != -1 {
			// Special handling for Enter in inputs
			if msg.Type == tea.KeyEnter {
				if m.FocusIndex == InputURL {
					if !m.Running {
						return m.startTest()
					}
				} else {
					m.cycleFocus(1)
				}
				return m, nil
			}

			m.Inputs[m.FocusIndex], cmd = m.Inputs[m.FocusIndex].Update(msg)
			return m, cmd
		}

		// 3. Navigation (If NOT focused on input)
		switch {
		case key.Matches(msg, keys.Run):
			if !m.Running {
				return m.startTest()
			}
		case key.Matches(msg, keys.Logs):
			m.ActiveView = ViewLogs
			m.updateViewport()
		case key.Matches(msg, keys.Metrics):
			m.ActiveView = ViewMetrics
			m.updateViewport()
		case key.Matches(msg, keys.Histo):
			m.ActiveView = ViewHistogram
			m.updateViewport()
		case key.Matches(msg, keys.PageUp):
			m.Viewport.ViewUp()
		case key.Matches(msg, keys.PageDown):
			m.Viewport.ViewDown()
		}

	case metricsMsg:
		if m.Running {
			cmds = append(cmds, m.waitForMsg())
			m.updateViewport()
		}

	case logMsg:
		m.appendLog(msg.text)
		if m.ActiveView == ViewLogs {
			atBottom := m.Viewport.AtBottom()
			m.updateViewport()
			if atBottom {
				m.Viewport.GotoBottom()
			}
		}
		cmds = append(cmds, m.waitForMsg())

	case progressMsg:
		if msg.done {
			m.stopTest()
		}
		cmds = append(cmds, m.waitForMsg())

	case spinner.TickMsg:
		if m.Running {
			m.Spinner, cmd = m.Spinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	m.Viewport, cmd = m.Viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m Ui) View() string {
	if m.Height < 10 {
		return "Terminal too small"
	}

	// 1. Header
	header := m.renderHeader()

	// 2. Config Panel
	config := m.renderConfig()

	// 3. Stats (only if running or has data)
	stats := ""
	if m.Running || m.Metrics.TotalRequests.Load() > 0 {
		stats = m.renderStats()
	}

	// 4. Tabs
	tabs := m.renderTabs()

	// 5. Footer
	footer := m.renderFooter()

	// Calculate Viewport Height
	fixedHeight := lipgloss.Height(header) + lipgloss.Height(config) + lipgloss.Height(stats) + lipgloss.Height(tabs) + lipgloss.Height(footer)
	availHeight := m.Height - fixedHeight
	if availHeight < 5 {
		availHeight = 5
	}
	m.Viewport.Height = availHeight

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		config,
		stats,
		tabs,
		m.Viewport.View(),
		footer,
	)
}

// --- Renderers ---

func (m Ui) renderHeader() string {
	logo := lipgloss.NewStyle().Foreground(pColor).Bold(true).Render("AGBERO")
	desc := lipgloss.NewStyle().Foreground(tColor).Render(" Load Tester")

	status := lipgloss.NewStyle().Foreground(lipgloss.Color("#555")).Render("IDLE")
	if m.Running {
		status = lipgloss.NewStyle().Foreground(lipgloss.Color("#34D399")).Render(m.Spinner.View() + " RUNNING")
	}

	gap := m.Width - lipgloss.Width(logo) - lipgloss.Width(desc) - lipgloss.Width(status) - 2
	if gap < 0 {
		gap = 0
	}

	return headerStyle.Width(m.Width).Render(
		lipgloss.JoinHorizontal(lipgloss.Center, logo, desc, strings.Repeat(" ", gap), status),
	)
}

func (m Ui) renderConfig() string {
	// Helper for inputs
	field := func(id int, label string, width int) string {
		m.Inputs[id].Width = width
		s := inputStyle
		if m.FocusIndex == id {
			s = focusStyle
		}
		return lipgloss.JoinVertical(lipgloss.Left,
			labelStyle.Render(label),
			s.Render(m.Inputs[id].View()),
		)
	}

	// Row 1: Method | URL | Concurrency
	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		field(InputMethod, "METHOD", 8),
		field(InputURL, "URL", m.Width-35),
		field(InputConcurrency, "WORKERS", 8),
	)

	// Row 2: Duration | Requests | Rate
	row2 := lipgloss.JoinHorizontal(lipgloss.Top,
		field(InputDuration, "DURATION", 10),
		field(InputRequests, "REQUESTS", 10),
		field(InputRate, "RATE/s", 10),
	)

	// Row 3: Headers | Body (Split 50/50)
	halfW := (m.Width / 2) - 4
	if halfW < 10 {
		halfW = 10
	}
	row3 := lipgloss.JoinHorizontal(lipgloss.Top,
		field(InputHeaders, "HEADERS", halfW),
		field(InputBody, "BODY", halfW),
	)

	return panelStyle.Width(m.Width - 2).Render(
		lipgloss.JoinVertical(lipgloss.Left, row1, row2, row3),
	)
}

func (m Ui) renderStats() string {
	snap := m.Metrics.Snapshot()

	// Progress Bar
	var prog string
	if m.Running && (m.Config.Requests > 0 || m.Config.Duration > 0) {
		pct := 0.0
		if m.Config.Duration > 0 {
			elapsed := time.Since(m.StartTime).Seconds()
			pct = elapsed / m.Config.Duration.Seconds()
		} else if m.Config.Requests > 0 {
			pct = float64(snap.TotalRequests) / float64(m.Config.Requests)
		}
		if pct > 1.0 {
			pct = 1.0
		}
		m.ProgressBar.Width = m.Width - 4
		prog = "\n" + m.ProgressBar.ViewAs(pct)
	}

	stat := func(label, val string, color lipgloss.Color) string {
		return cardStyle.Render(lipgloss.JoinVertical(lipgloss.Center,
			cardLabelStyle.Render(label),
			cardValueStyle.Foreground(color).Render(val),
		))
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top,
		stat("TOTAL", fmt.Sprintf("%d", snap.TotalRequests), wColor),
		stat("RPS", fmt.Sprintf("%d", snap.RequestsPerSec), pColor),
		stat("ERRORS", fmt.Sprintf("%d", snap.ErrorCount), lipgloss.Color("#F87171")),
		stat("AVG LAT", fmt.Sprintf("%.0fms", snap.AvgLatencyMs), lipgloss.Color("#FBBF24")),
	)

	return panelStyle.Width(m.Width - 2).Render(row + prog)
}

func (m Ui) renderTabs() string {
	opts := []string{"1. LOGS", "2. METRICS", "3. HISTOGRAM"}
	var rendered []string

	for i, opt := range opts {
		if i == m.ActiveView {
			rendered = append(rendered, activeTabStyle.Render(opt))
		} else {
			rendered = append(rendered, tabStyle.Render(opt))
		}
	}

	tabsWidth := lipgloss.Width(lipgloss.JoinHorizontal(lipgloss.Top, rendered...))
	gap := m.Width - tabsWidth - 2
	if gap < 0 {
		gap = 0
	}
	border := lipgloss.NewStyle().Foreground(lipgloss.Color("#404040")).Render(strings.Repeat("─", gap))

	return lipgloss.JoinHorizontal(lipgloss.Bottom, append(rendered, border)...)
}

func (m Ui) renderFooter() string {
	return lipgloss.NewStyle().
		Width(m.Width).
		Background(sColor).
		Padding(0, 1).
		Render(m.Help.View(keys))
}

// --- Logic Helpers ---

func (m *Ui) startTest() (Ui, tea.Cmd) {
	m.Config.Method = m.Inputs[InputMethod].Value()
	m.Config.Targets = []string{m.Inputs[InputURL].Value()}

	c, _ := strconv.Atoi(m.Inputs[InputConcurrency].Value())
	if c < 1 {
		c = 1
	}
	m.Config.Concurrency = c

	r, _ := strconv.Atoi(m.Inputs[InputRequests].Value())
	m.Config.Requests = r

	d, _ := time.ParseDuration(m.Inputs[InputDuration].Value())
	m.Config.Duration = d

	rl, _ := strconv.Atoi(m.Inputs[InputRate].Value())
	m.Config.RateLimit = rl

	m.Metrics = &Metrics{}
	m.Logs = []string{styleLog("SYS", "Initializing...", logInfoStyle)}
	m.StartTime = time.Now()
	m.Running = true
	m.updateViewport()

	limit := uint64(m.Config.Requests)
	if limit == 0 {
		limit = math.MaxUint64
	}

	m.WorkerPool = NewWorkerPool(m.Config, m.Metrics, m.msgChan, limit)

	return *m, tea.Batch(
		func() tea.Msg {
			go m.WorkerPool.Start()
			return nil
		},
		m.waitForMsg(),
	)
}

func (m *Ui) stopTest() {
	m.Running = false
	if m.WorkerPool != nil {
		m.WorkerPool.Stop()
	}
	m.Logs = append(m.Logs, styleLog("SYS", "Stopped.", logErrStyle))
	m.updateViewport()
}

func (m *Ui) cycleFocus(dir int) {
	if m.FocusIndex != -1 {
		m.Inputs[m.FocusIndex].Blur()
	}
	m.FocusIndex += dir
	if m.FocusIndex >= len(m.Inputs) {
		m.FocusIndex = 0
	} else if m.FocusIndex < 0 {
		m.FocusIndex = len(m.Inputs) - 1
	}
	m.Inputs[m.FocusIndex].Focus()
}

func (m *Ui) resizeComponents() {
	m.Viewport.Width = m.Width
}

func (m *Ui) appendLog(txt string) {
	t := time.Now().Format("15:04:05")
	line := fmt.Sprintf("%s %s", logTimeStyle.Render(t), txt)
	m.Logs = append(m.Logs, line)
	if len(m.Logs) > 500 {
		m.Logs = m.Logs[len(m.Logs)-500:]
	}
}

func (m *Ui) updateViewport() {
	var content string
	switch m.ActiveView {
	case ViewLogs:
		if len(m.Logs) == 0 {
			content = "Waiting for logs..."
		} else {
			content = strings.Join(m.Logs, "\n")
		}
	case ViewMetrics:
		content = m.renderMetricsDetail()
	case ViewHistogram:
		content = m.renderHistogram()
	}
	m.Viewport.SetContent(content)
}

func styleLog(prefix, msg string, style lipgloss.Style) string {
	return fmt.Sprintf("%s %s", style.Render(prefix), msg)
}

func (m Ui) renderMetricsDetail() string {
	snap := m.Metrics.Snapshot()
	return fmt.Sprintf(`
  PERFORMANCE METRICS
  ───────────────────
  Total Requests:   %d
  Success Count:    %d
  Error Count:      %d
  Success Rate:     %.2f%%
  Throughput:       %.2f MB/s
  Active Conns:     %d

  LATENCY
  ───────
  Average:          %.2f ms
  Minimum:          %.2f ms
  Maximum:          %.2f ms

  STATUS CODES
  ────────────
  2xx: %d
  3xx: %d
  4xx: %d
  5xx: %d
`,
		snap.TotalRequests, snap.SuccessCount, snap.ErrorCount,
		snap.SuccessRate, snap.ThroughputMBps, snap.ActiveConnections,
		snap.AvgLatencyMs, snap.MinLatencyMs, snap.MaxLatencyMs,
		snap.StatusCode2xx, snap.StatusCode3xx, snap.StatusCode4xx, snap.StatusCode5xx,
	)
}

func (m Ui) renderHistogram() string {
	var sb strings.Builder
	sb.WriteString("\n  LATENCY HISTOGRAM\n  ─────────────────\n\n")

	labels := []string{"<10ms", "10-50", "50-100", "100-250", "250-500", "500-1s", "1s-2s", "2s-5s", "5s-10s", ">10s"}
	var maxVal uint64
	for i := range m.Metrics.LatencyBuckets {
		val := m.Metrics.LatencyBuckets[i].Load()
		if val > maxVal {
			maxVal = val
		}
	}

	for i, label := range labels {
		val := m.Metrics.LatencyBuckets[i].Load()
		barLen := 0
		if maxVal > 0 {
			barLen = int((float64(val) / float64(maxVal)) * 50)
		}
		bar := strings.Repeat("█", barLen)
		sb.WriteString(fmt.Sprintf("  %-8s │ %s %d\n", label, bar, val))
	}
	return sb.String()
}
