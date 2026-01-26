// model.go
package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- Constants & Styles ---
var (
	// Colors
	primaryColor    = lipgloss.Color("#FF6C37") // Postman orange
	secondaryColor  = lipgloss.Color("#9CA3AF")
	successColor    = lipgloss.Color("#34D399")
	warningColor    = lipgloss.Color("#FBBF24")
	errorColor      = lipgloss.Color("#F87171")
	backgroundColor = lipgloss.Color("#121212")
	surfaceColor    = lipgloss.Color("#262626")
	borderColor     = lipgloss.Color("#404040")
	textPrimary     = lipgloss.Color("#FFFFFF")
	textSecondary   = lipgloss.Color("#A3A3A3")

	// Base Styles
	appStyle = lipgloss.NewStyle().
			Background(backgroundColor).
			Foreground(textPrimary)

	// Header
	headerStyle = lipgloss.NewStyle().
			Background(primaryColor).
			Foreground(textPrimary).
			Bold(true).
			Padding(0, 1)

	// Request Bar
	requestBarStyle = lipgloss.NewStyle().
			Background(surfaceColor).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(borderColor).
			Padding(1, 1)

	methodSelectorStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#171717")).
				Foreground(textPrimary).
				Padding(0, 1).
				MarginRight(1)

	methodOptionStyle = lipgloss.NewStyle().
				Foreground(textSecondary).
				Padding(0, 1)

	methodOptionSelectedStyle = lipgloss.NewStyle().
					Foreground(primaryColor).
					Bold(true).
					Padding(0, 1)

	urlInputStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#171717")).
			Padding(0, 1)

	sendButtonStyle = lipgloss.NewStyle().
			Background(primaryColor).
			Foreground(textPrimary).
			Bold(true).
			Padding(0, 3).
			Align(lipgloss.Center)

	sendButtonHoverStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#FF8C5C")).
				Foreground(textPrimary).
				Bold(true).
				Padding(0, 3).
				Align(lipgloss.Center)

	// Configuration Panel
	configPanelStyle = lipgloss.NewStyle().
				Background(surfaceColor).
				Border(lipgloss.NormalBorder(), false, false, true, false).
				BorderForeground(borderColor).
				Padding(1)

	configLabelStyle = lipgloss.NewStyle().
				Foreground(secondaryColor).
				Width(14).
				Align(lipgloss.Right).
				PaddingRight(1)

	configInputStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#171717")).
				Foreground(textPrimary).
				Padding(0, 1)

	configInputFocusedStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#171717")).
				Foreground(textPrimary).
				Border(lipgloss.NormalBorder(), false, false, true, false).
				BorderForeground(primaryColor).
				Padding(0, 1)

	// Dashboard
	dashboardStyle = lipgloss.NewStyle().
			Background(surfaceColor).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(borderColor).
			Padding(1)

	statCardStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#1E1E1E")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Padding(0, 1).
			MarginRight(1)

	statValueStyle = lipgloss.NewStyle().
			Foreground(textPrimary).
			Bold(true)

	statLabelStyle = lipgloss.NewStyle().
			Foreground(textSecondary)

	// Response/Log Panel
	responsePanelStyle = lipgloss.NewStyle().
				Background(backgroundColor)

	tabActiveStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(primaryColor).
			Padding(0, 2).
			Bold(true)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(textSecondary).
				Padding(0, 2)

	// Status Bar
	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#000000")).
			Foreground(textSecondary).
			Padding(0, 1)

	keyStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	helpStyle = lipgloss.NewStyle().
			Foreground(textSecondary)

	methods = []string{"GET", "POST", "PUT", "DEL", "PAT", "HED", "OPT"}
)

// Key mappings
type ModelKeyMap struct {
	Run       key.Binding
	Stop      key.Binding
	FocusURL  key.Binding
	FocusNext key.Binding
	FocusPrev key.Binding
	Quit      key.Binding
	Help      key.Binding
}

var modelKeys = ModelKeyMap{
	Run: key.NewBinding(
		key.WithKeys("enter", "ctrl+r"),
		key.WithHelp("enter", "run"),
	),
	Stop: key.NewBinding(
		key.WithKeys("ctrl+c", "esc"),
		key.WithHelp("esc", "stop"),
	),
	FocusURL: key.NewBinding(
		key.WithKeys("ctrl+l"),
		key.WithHelp("ctrl+l", "url"),
	),
	FocusNext: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next"),
	),
	FocusPrev: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+q"),
		key.WithHelp("ctrl+q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
}

// Input indices
const (
	InputMethod = iota
	InputURL
	InputConcurrency
	InputRequests
	InputDuration
	InputRateLimit
	InputHeaders
	InputBody
	NumNonButtonInputs
)

const TotalFocusableElements = NumNonButtonInputs + 1

// Tab indices
const (
	TabConsole = iota
	TabMetrics
	TabHistogram
	NumTabs
)

type Model struct {
	Config  Config
	Metrics *Metrics

	// UI State
	Running            bool
	ActiveTab          int
	ShowHelp           bool
	Width, Height      int
	StartTime          time.Time
	EndTime            time.Time
	StatusMessage      string
	StatusMessageTimer *time.Timer

	// UI Components
	Inputs       []textinput.Model
	FocusIndex   int
	MethodIndex  int
	Progress     progress.Model
	Spinner      spinner.Model
	ResponseView viewport.Model
	MetricsTable table.Model
	KeyMap       ModelKeyMap

	// Data
	Logs       []string
	Responses  []string
	WorkerPool *Pool
	msgChan    chan tea.Msg

	// Layout
	layout struct {
		headerHeight    int
		requestHeight   int
		configHeight    int
		dashboardHeight int
		responseHeight  int
		statusHeight    int
	}
}

// Added missing struct definition
type savedConfigMsg struct {
	message string
}

func NewModel(cfg Config) Model {
	inputs := make([]textinput.Model, NumNonButtonInputs)

	inputs[InputMethod] = textinput.New()
	inputs[InputMethod].SetValue(cfg.Method)

	inputs[InputURL] = textinput.New()
	inputs[InputURL].Placeholder = "http://localhost:8080"
	inputs[InputURL].Focus()
	if len(cfg.Targets) > 0 {
		inputs[InputURL].SetValue(cfg.Targets[0])
	}

	inputs[InputConcurrency] = textinput.New()
	inputs[InputConcurrency].Placeholder = "10"
	inputs[InputConcurrency].SetValue(fmt.Sprintf("%d", max(1, cfg.Concurrency)))

	inputs[InputRequests] = textinput.New()
	inputs[InputRequests].Placeholder = "0 (∞)"
	inputs[InputRequests].SetValue(fmt.Sprintf("%d", max(0, cfg.Requests)))

	inputs[InputDuration] = textinput.New()
	inputs[InputDuration].Placeholder = "10s"
	if cfg.Duration > 0 {
		inputs[InputDuration].SetValue(cfg.Duration.String())
	}

	inputs[InputRateLimit] = textinput.New()
	inputs[InputRateLimit].Placeholder = "0"
	inputs[InputRateLimit].SetValue(fmt.Sprintf("%d", cfg.RateLimit))

	inputs[InputHeaders] = textinput.New()
	inputs[InputHeaders].Placeholder = "Key: Value"
	if len(cfg.Headers) > 0 {
		inputs[InputHeaders].SetValue(strings.Join(cfg.Headers, ", "))
	}

	inputs[InputBody] = textinput.New()
	inputs[InputBody].Placeholder = "JSON"
	inputs[InputBody].SetValue(cfg.Body)

	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithoutPercentage(),
		progress.WithScaledGradient("#FF6C37", "#FF8C5C"),
	)

	spin := spinner.New()
	spin.Spinner = spinner.Pulse
	spin.Style = lipgloss.NewStyle().Foreground(primaryColor)

	responseView := viewport.New(80, 20)
	responseView.SetContent("Ready. Enter URL and press Enter to start.")

	// Table setup
	columns := []table.Column{{Title: "Metric", Width: 20}, {Title: "Value", Width: 15}, {Title: "Status", Width: 10}}
	rows := []table.Row{{"Requests", "0", "Idle"}, {"Success", "0%", "Idle"}}
	metricsTable := table.New(table.WithColumns(columns), table.WithRows(rows), table.WithFocused(false), table.WithHeight(6))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(borderColor).BorderBottom(true).Bold(false)
	metricsTable.SetStyles(s)

	methodIndex := 0
	for i, m := range methods {
		if m == cfg.Method {
			methodIndex = i
			break
		}
	}

	if cfg.Concurrency == 0 {
		cfg.Concurrency = 10
	}
	if cfg.Method == "" {
		cfg.Method = "GET"
	}

	return Model{
		Config:       cfg,
		Metrics:      &Metrics{},
		Inputs:       inputs,
		FocusIndex:   InputURL,
		MethodIndex:  methodIndex,
		ActiveTab:    TabConsole,
		Progress:     prog,
		Spinner:      spin,
		ResponseView: responseView,
		MetricsTable: metricsTable,
		KeyMap:       modelKeys,
		Logs:         []string{},
		msgChan:      make(chan tea.Msg, 1000),
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.Inputs[m.FocusIndex].Focus(), m.waitForMsg(), m.Spinner.Tick, updateMetricsAfter(time.Second))
}

func (m *Model) waitForMsg() tea.Cmd {
	return func() tea.Msg { return <-m.msgChan }
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	if m.StatusMessageTimer != nil {
		select {
		case <-m.StatusMessageTimer.C:
			m.StatusMessage = ""
			m.StatusMessageTimer.Stop()
			m.StatusMessageTimer = nil
		default:
		}
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if key.Matches(msg, m.KeyMap.Quit) {
			if m.WorkerPool != nil {
				m.WorkerPool.Stop()
			}
			return m, tea.Quit
		}
		if key.Matches(msg, m.KeyMap.Help) {
			m.ShowHelp = !m.ShowHelp
			return m, nil
		}
		if m.ShowHelp {
			return m, nil // Trap keys in help
		}

		if key.Matches(msg, m.KeyMap.Run) {
			return m.toggleRun()
		}
		if key.Matches(msg, m.KeyMap.Stop) && m.Running {
			m.stopTest()
			return m, nil
		}

		switch {
		case key.Matches(msg, m.KeyMap.FocusURL):
			m.setFocus(InputURL)
		case key.Matches(msg, m.KeyMap.FocusNext):
			m.focusNext()
		case key.Matches(msg, m.KeyMap.FocusPrev):
			m.focusPrev()
		}

		if m.FocusIndex == InputMethod {
			switch msg.String() {
			case "left", "h":
				m.MethodIndex = (m.MethodIndex - 1 + len(methods)) % len(methods)
				m.Config.Method = methods[m.MethodIndex]
				m.Inputs[InputMethod].SetValue(methods[m.MethodIndex])
			case "right", "l":
				m.MethodIndex = (m.MethodIndex + 1) % len(methods)
				m.Config.Method = methods[m.MethodIndex]
				m.Inputs[InputMethod].SetValue(methods[m.MethodIndex])
			}
		}

		switch msg.String() {
		case "1":
			m.ActiveTab = TabConsole
			m.updateResponseView()
		case "2":
			m.ActiveTab = TabMetrics
			m.updateResponseView()
		case "3":
			m.ActiveTab = TabHistogram
			m.updateResponseView()
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.calculateLayout()
		m.updateViewportSize()

	case spinner.TickMsg:
		if m.Running {
			m.Spinner, cmd = m.Spinner.Update(msg)
			cmds = append(cmds, cmd)
		}

	case progressMsg:
		if msg.total > 0 {
			m.Progress.SetPercent(float64(msg.completed) / float64(msg.total))
		}
		if msg.done && m.Running {
			m.stopTest()
			m.StatusMessage = "Done"
			m.startStatusMessageTimer()
		}
		cmds = append(cmds, m.waitForMsg())

	case metricsMsg:
		snap := m.Metrics.Snapshot()
		m.updateMetricsTable(snap)
		if m.ActiveTab == TabMetrics || m.ActiveTab == TabHistogram {
			m.updateResponseView()
		}
		cmds = append(cmds, m.waitForMsg(), updateMetricsAfter(500*time.Millisecond))

	case logMsg:
		m.Logs = append(m.Logs, styleLogLine(msg.text))
		if len(m.Logs) > 500 {
			m.Logs = m.Logs[len(m.Logs)-500:]
		}
		if m.ActiveTab == TabConsole {
			m.updateResponseView()
		}
		cmds = append(cmds, m.waitForMsg())

	case savedConfigMsg:
		m.StatusMessage = msg.message
		m.startStatusMessageTimer()
	}

	if m.FocusIndex > InputMethod && m.FocusIndex < NumNonButtonInputs {
		m.Inputs[m.FocusIndex], cmd = m.Inputs[m.FocusIndex].Update(msg)
		cmds = append(cmds, cmd)
	}

	var vcmd tea.Cmd
	m.ResponseView, vcmd = m.ResponseView.Update(msg)
	cmds = append(cmds, vcmd)

	return m, tea.Batch(cmds...)
}

func (m *Model) calculateLayout() {
	m.layout.headerHeight = 1
	m.layout.requestHeight = 3
	m.layout.configHeight = 6 // Compacted
	m.layout.dashboardHeight = 6
	m.layout.statusHeight = 1

	used := m.layout.headerHeight + m.layout.requestHeight + m.layout.configHeight + m.layout.dashboardHeight + m.layout.statusHeight
	m.layout.responseHeight = m.Height - used
	if m.layout.responseHeight < 5 {
		m.layout.responseHeight = 5
	}
}

func (m *Model) updateViewportSize() {
	m.ResponseView.Width = m.Width - 4
	m.ResponseView.Height = m.layout.responseHeight - 2
}

func (m *Model) setFocus(index int) {
	if m.FocusIndex >= 0 && m.FocusIndex < NumNonButtonInputs {
		m.Inputs[m.FocusIndex].Blur()
	}
	if index == -1 {
		m.FocusIndex = -1
		return
	}
	if index >= 0 && index < NumNonButtonInputs {
		m.Inputs[index].Focus()
	}
	m.FocusIndex = index
}

func (m *Model) focusNext() {
	next := m.FocusIndex + 1
	if next > NumNonButtonInputs { // Wrap around
		next = 0 // InputMethod
	}
	m.setFocus(next)
}

func (m *Model) focusPrev() {
	prev := m.FocusIndex - 1
	if prev < 0 {
		prev = NumNonButtonInputs // Button
	}
	m.setFocus(prev)
}

func (m Model) toggleRun() (Model, tea.Cmd) {
	if m.Running {
		m.stopTest()
		return m, nil
	}
	return m.startTest()
}

func (m Model) startTest() (Model, tea.Cmd) {
	target := strings.TrimSpace(m.Inputs[InputURL].Value())
	if target == "" {
		m.StatusMessage = "URL required"
		m.startStatusMessageTimer()
		return m, nil
	}
	m.Config.Targets = []string{target}

	c, _ := strconv.Atoi(m.Inputs[InputConcurrency].Value())
	if c > 0 {
		m.Config.Concurrency = c
	}

	r, _ := strconv.Atoi(m.Inputs[InputRequests].Value())
	m.Config.Requests = r

	d, _ := time.ParseDuration(m.Inputs[InputDuration].Value())
	m.Config.Duration = d

	rl, _ := strconv.Atoi(m.Inputs[InputRateLimit].Value())
	m.Config.RateLimit = rl

	// Parse headers
	m.Config.Headers = []string{}
	parts := strings.Split(m.Inputs[InputHeaders].Value(), ",")
	for _, p := range parts {
		if strings.Contains(p, ":") {
			m.Config.Headers = append(m.Config.Headers, strings.TrimSpace(p))
		}
	}

	m.Config.Body = m.Inputs[InputBody].Value()
	m.Config.Method = m.Inputs[InputMethod].Value()

	m.Running = true
	m.StartTime = time.Now()
	m.EndTime = time.Time{}
	m.Metrics = &Metrics{}
	m.Logs = []string{styleLogLine("INFO: Starting...")}
	m.updateResponseView()
	m.Progress.SetPercent(0)

	// Fix infinite progress bar
	progTotal := uint64(m.Config.Requests)
	m.WorkerPool = NewWorkerPool(m.Config, m.Metrics, m.msgChan, progTotal)

	cmds := []tea.Cmd{
		func() tea.Msg {
			go m.WorkerPool.Start()
			return nil
		},
		m.Spinner.Tick,
		updateMetricsAfter(100 * time.Millisecond),
	}
	m.setFocus(-1)
	return m, tea.Batch(cmds...)
}

func (m *Model) stopTest() {
	m.Running = false
	m.EndTime = time.Now()
	if m.WorkerPool != nil {
		m.WorkerPool.Stop()
		m.WorkerPool = nil
	}
	m.Logs = append(m.Logs, styleLogLine("INFO: Stopped"))
	m.updateResponseView()
	m.StatusMessage = "Stopped"
	m.startStatusMessageTimer()
}

func (m *Model) updateResponseView() {
	var content string
	switch m.ActiveTab {
	case TabConsole:
		content = strings.Join(m.Logs, "\n")
		if content == "" {
			content = "No logs."
		}
	case TabMetrics:
		content = m.renderMetricsDetail()
	case TabHistogram:
		content = m.renderHistogramDetail()
	}
	m.ResponseView.SetContent(content)
	m.ResponseView.GotoBottom()
}

func (m *Model) updateMetricsTable(snap MetricsSnapshot) {
	rows := []table.Row{
		{"Reqs", fmt.Sprintf("%d", snap.TotalRequests), getStatusEmoji(snap.SuccessRate)},
		{"Rate", fmt.Sprintf("%.1f%%", snap.SuccessRate), getStatusColor(snap.SuccessRate)},
		{"Lat", fmt.Sprintf("%.0fms", snap.AvgLatencyMs), getLatencyStatus(snap.AvgLatencyMs)},
		{"RPS", fmt.Sprintf("%d", snap.RequestsPerSec), ""},
	}
	m.MetricsTable.SetRows(rows)
}

func (m *Model) startStatusMessageTimer() {
	if m.StatusMessageTimer != nil {
		m.StatusMessageTimer.Stop()
	}
	m.StatusMessageTimer = time.NewTimer(3 * time.Second)
}

// --- View Rendering ---

func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "Loading..."
	}

	// Calculate strict effective width to prevent overflow
	effWidth := m.Width
	if effWidth > 2 {
		effWidth -= 2 // Safety margin
	}

	header := m.renderHeader(effWidth)
	requestBar := m.renderRequestBar(effWidth)
	configPanel := m.renderConfigPanel(effWidth)
	dashboard := m.renderDashboard(effWidth)
	responsePanel := m.renderResponsePanel(effWidth)
	statusBar := m.renderStatusBar(effWidth)

	view := lipgloss.JoinVertical(lipgloss.Left,
		header,
		requestBar,
		configPanel,
		dashboard,
		responsePanel,
		statusBar,
	)

	if m.ShowHelp {
		// Overlay help
		return appStyle.Width(m.Width).Height(m.Height).Render(m.renderHelp(effWidth))
	}

	return appStyle.Width(m.Width).Height(m.Height).Render(view)
}

func (m Model) renderHeader(w int) string {
	title := "OPPOR"
	status := "IDLE"
	if m.Running {
		status = fmt.Sprintf("RUNNING %s", m.Spinner.View())
	}

	// Manual alignment - Using lipgloss.Width to calculate length
	avail := w - len(title) - lipgloss.Width(status) - 4
	if avail < 0 {
		avail = 0
	}
	gap := strings.Repeat(" ", avail)

	return headerStyle.Width(w).Render(title + gap + status)
}

func (m Model) renderRequestBar(w int) string {
	// Fixed widths for button and method
	methodW := 24
	btnW := 12

	// Dynamic URL width
	urlW := w - methodW - btnW - 6 // margins
	if urlW < 10 {
		urlW = 10
	}

	methodSel := methodSelectorStyle.Width(methodW).Render(m.renderMethodSelector())

	urlStyle := urlInputStyle.Width(urlW)
	if m.FocusIndex == InputURL {
		urlStyle = urlStyle.Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(primaryColor)
	}
	urlIn := urlStyle.Render(m.Inputs[InputURL].View())

	btn := m.renderSendButton(btnW)

	return requestBarStyle.Width(w).Render(
		lipgloss.JoinHorizontal(lipgloss.Top, methodSel, urlIn, btn),
	)
}

func (m Model) renderSendButton(w int) string {
	txt := "SEND"
	style := sendButtonStyle.Width(w)
	if m.Running {
		txt = "STOP"
		style = style.Background(errorColor)
	} else if m.FocusIndex == NumNonButtonInputs {
		style = sendButtonHoverStyle.Width(w)
	}
	return style.Render(txt)
}

func (m Model) renderMethodSelector() string {
	var s strings.Builder
	for i, met := range methods {
		if i == m.MethodIndex {
			s.WriteString(methodOptionSelectedStyle.Render(met))
		} else {
			s.WriteString(methodOptionStyle.Render(met))
		}
		if i < len(methods)-1 {
			s.WriteString(" ")
		}
	}
	return s.String()
}

func (m Model) renderConfigPanel(w int) string {
	// We'll do 2 columns if space permits, else 1
	// Col width = (w / 2) - padding
	colW := (w / 2) - 4
	if colW < 30 {
		colW = w - 4 // stacked
	}

	// Helper to render a row (Label + Input)
	renderRow := func(label string, idx int) string {
		l := configLabelStyle.Render(label)
		// Input fills remaining space in col
		inW := colW - lipgloss.Width(l) - 2
		if inW < 10 {
			inW = 10
		}

		s := configInputStyle.Width(inW)
		if m.FocusIndex == idx {
			s = configInputFocusedStyle.Width(inW)
		}

		val := m.Inputs[idx].View()
		// Force clip value if too long to prevent wrap
		if len(val) > inW {
			val = val[len(val)-inW:]
		}

		return lipgloss.JoinHorizontal(lipgloss.Left, l, s.Render(val))
	}

	col1 := lipgloss.JoinVertical(lipgloss.Left,
		renderRow("Concurrency", InputConcurrency),
		renderRow("Requests", InputRequests),
		renderRow("Duration", InputDuration),
	)

	col2 := lipgloss.JoinVertical(lipgloss.Left,
		renderRow("Rate Limit", InputRateLimit),
		renderRow("Headers", InputHeaders),
		renderRow("Body", InputBody),
	)

	if colW == w-4 {
		return configPanelStyle.Width(w).Render(lipgloss.JoinVertical(lipgloss.Left, col1, col2))
	}
	return configPanelStyle.Width(w).Render(lipgloss.JoinHorizontal(lipgloss.Top, col1, "  ", col2))
}

func (m Model) renderDashboard(w int) string {
	snap := m.Metrics.Snapshot()

	// Dynamic calculation for 4 cards
	cardW := (w - 10) / 4
	if cardW < 15 {
		cardW = 15
	}

	renderCard := func(label, val string) string {
		return statCardStyle.Width(cardW).Render(
			lipgloss.JoinVertical(lipgloss.Left,
				statLabelStyle.Render(label),
				statValueStyle.Render(val),
			),
		)
	}

	cards := lipgloss.JoinHorizontal(lipgloss.Top,
		renderCard("REQS", fmt.Sprintf("%d", snap.TotalRequests)),
		renderCard("RPS", fmt.Sprintf("%d", snap.RequestsPerSec)),
		renderCard("OK", fmt.Sprintf("%.0f%%", snap.SuccessRate)),
		renderCard("LAT", fmt.Sprintf("%.0fms", snap.AvgLatencyMs)),
	)

	// Add progress bar if needed
	if m.Running && m.Config.Requests > 0 {
		m.Progress.Width = w - 20
		prog := lipgloss.NewStyle().PaddingTop(1).Render(m.Progress.View())
		return dashboardStyle.Width(w).Render(lipgloss.JoinVertical(lipgloss.Left, cards, prog))
	}

	return dashboardStyle.Width(w).Render(cards)
}

func (m Model) renderResponsePanel(w int) string {
	// Tab bar
	tabs := []string{"LOGS", "METRICS", "HISTO"}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.ActiveTab {
			renderedTabs = append(renderedTabs, tabActiveStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, tabInactiveStyle.Render(t))
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Bottom, renderedTabs...)

	// Border between tabs and content
	border := lipgloss.NewStyle().Width(w).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(borderColor).Render("")

	return lipgloss.JoinVertical(lipgloss.Left,
		tabBar,
		border,
		responsePanelStyle.Width(w).Render(m.ResponseView.View()),
	)
}

func (m Model) renderMetricsDetail() string {
	snap := m.Metrics.Snapshot()
	s := fmt.Sprintf(`
  Total: %d
  Success: %d (%.1f%%)
  Errors: %d
  RPS: %d
  Avg Latency: %.0fms
  Min: %.0fms
  Max: %.0fms
  Codes: 2xx:%d, 3xx:%d, 4xx:%d, 5xx:%d
`, snap.TotalRequests, snap.SuccessCount, snap.SuccessRate, snap.ErrorCount,
		snap.RequestsPerSec, snap.AvgLatencyMs, snap.MinLatencyMs, snap.MaxLatencyMs,
		snap.StatusCode2xx, snap.StatusCode3xx, snap.StatusCode4xx, snap.StatusCode5xx)
	return s
}

func (m Model) renderHistogramDetail() string {
	// Simplified histogram text
	var sb strings.Builder
	sb.WriteString("Latency Distribution:\n\n")
	labels := []string{"<10ms", "<50ms", "<100ms", "<250ms", "<500ms", "<1s", "<2s", "<5s", "5s+", "10s+"}
	var maxVal uint64 = 0
	for _, b := range m.Metrics.LatencyBuckets {
		v := b.Load()
		if v > maxVal {
			maxVal = v
		}
	}

	for i, b := range m.Metrics.LatencyBuckets {
		if i >= len(labels) {
			break
		}
		val := b.Load()
		barLen := 0
		if maxVal > 0 {
			barLen = int((float64(val) / float64(maxVal)) * 40)
		}
		bar := strings.Repeat("|", barLen)
		sb.WriteString(fmt.Sprintf("%-8s %s %d\n", labels[i], bar, val))
	}
	return sb.String()
}

func (m Model) renderStatusBar(w int) string {
	dur := "0s"
	if m.Running {
		dur = time.Since(m.StartTime).Round(time.Second).String()
	}

	status := m.StatusMessage
	if status == "" {
		status = "Ready"
	}

	left := fmt.Sprintf(" %s | %s", dur, status)
	right := "CTRL+Q: Quit | ?: Help "

	space := w - len(left) - len(right)
	if space < 0 {
		space = 0
	}

	return statusBarStyle.Width(w).Render(left + strings.Repeat(" ", space) + right)
}

func (m Model) renderHelp(w int) string {
	// Just a simple overlay
	return lipgloss.Place(w, m.Height, lipgloss.Center, lipgloss.Center,
		lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Background(surfaceColor).Padding(1, 2).Render(
			"HELP\n\nEnter/Ctrl+R: Run\nTab: Next Field\nCtrl+L: Focus URL\nCtrl+Q: Quit",
		),
	)
}

// --- Helpers ---
func getStatusEmoji(rate float64) string {
	if rate > 95 {
		return "ok"
	}
	return "!!"
}

func getStatusColor(rate float64) string {
	if rate > 95 {
		return lipgloss.NewStyle().Foreground(successColor).Render("OK")
	}
	return lipgloss.NewStyle().Foreground(errorColor).Render("LOW")
}

func getLatencyStatus(lat float64) string {
	if lat < 200 {
		return lipgloss.NewStyle().Foreground(successColor).Render("FAST")
	}
	return lipgloss.NewStyle().Foreground(warningColor).Render("SLOW")
}

func styleLogLine(line string) string {
	if strings.Contains(line, "ERROR") {
		return lipgloss.NewStyle().Foreground(errorColor).Render(line)
	}
	if strings.Contains(line, "INFO") {
		return lipgloss.NewStyle().Foreground(successColor).Render(line)
	}
	return lipgloss.NewStyle().Foreground(textSecondary).Render(line)
}
