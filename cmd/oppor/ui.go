package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
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

	methods = []string{"GET", "POST", "PUT", "DEL", "PAT", "HED", "OPT"}
)

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

type Ui struct {
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
	KeyMap       KeyMap
	Help         help.Model

	// Data
	Logs       []string
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

type savedConfigMsg struct {
	message string
}

type loadMsg struct {
	cfg Config
	err error
}

func NewModel(cfg Config) Ui {
	inputs := make([]textinput.Model, NumNonButtonInputs)

	inputs[InputMethod] = textinput.New()
	inputs[InputMethod].SetValue(cfg.Method)
	inputs[InputMethod].Width = 5

	inputs[InputURL] = textinput.New()
	inputs[InputURL].Placeholder = "http://localhost:8080"
	inputs[InputURL].Focus()
	if len(cfg.Targets) > 0 {
		inputs[InputURL].SetValue(strings.Join(cfg.Targets, ", "))
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

	return Ui{
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
		KeyMap:       defaultKeyMap,
		Help:         help.New(),
		Logs:         []string{},
		msgChan:      make(chan tea.Msg, 1000),
	}
}

func (m Ui) Init() tea.Cmd {
	return tea.Batch(m.Inputs[m.FocusIndex].Focus(), m.waitForMsg(), m.Spinner.Tick, updateMetricsAfter(time.Second))
}

func (m *Ui) waitForMsg() tea.Cmd {
	return func() tea.Msg { return <-m.msgChan }
}

func (m Ui) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		case key.Matches(msg, m.KeyMap.ToggleVerbose):
			m.Config.Verbose = !m.Config.Verbose
			m.StatusMessage = fmt.Sprintf("Verbose: %t", m.Config.Verbose)
			m.startStatusMessageTimer()
		case key.Matches(msg, m.KeyMap.ClearLogs):
			m.Logs = []string{}
			m.updateResponseView()
		case key.Matches(msg, m.KeyMap.SaveConfig):
			return m, func() tea.Msg {
				err := saveCurrentConfig(m.Config, "default")
				message := "Config saved"
				if err != nil {
					message = "Save failed: " + err.Error()
				}
				return savedConfigMsg{message: message}
			}
		case key.Matches(msg, m.KeyMap.LoadConfig):
			return m, func() tea.Msg {
				cfg, err := loadConfigPreset("default")
				return loadMsg{cfg: cfg, err: err}
			}
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

		// Set dynamic widths for inputs
		methodW := 35
		btnW := 12
		urlW := m.Width - methodW - btnW - 6
		if urlW < 10 {
			urlW = 10
		}
		m.Inputs[InputURL].Width = urlW - 2

		colW := (m.Width / 2) - 4
		if colW < 30 {
			colW = m.Width - 4
		}
		inW := colW - 14 - 2 // label width + padding
		if inW < 10 {
			inW = 10
		}
		for i := InputConcurrency; i < NumNonButtonInputs; i++ {
			m.Inputs[i].Width = inW - 2
		}
		m.Inputs[InputMethod].Width = 5

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

	case loadMsg:
		if msg.err != nil {
			m.StatusMessage = "Load failed: " + msg.err.Error()
		} else {
			m.Config = msg.cfg
			m.updateInputsFromConfig()
			m.StatusMessage = "Config loaded"
		}
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

func (m *Ui) updateInputsFromConfig() {
	m.Inputs[InputMethod].SetValue(m.Config.Method)
	for i, mth := range methods {
		if mth == m.Config.Method {
			m.MethodIndex = i
			break
		}
	}
	m.Inputs[InputURL].SetValue(strings.Join(m.Config.Targets, ", "))
	m.Inputs[InputConcurrency].SetValue(strconv.Itoa(m.Config.Concurrency))
	m.Inputs[InputRequests].SetValue(strconv.Itoa(m.Config.Requests))
	if m.Config.Duration > 0 {
		m.Inputs[InputDuration].SetValue(m.Config.Duration.String())
	} else {
		m.Inputs[InputDuration].SetValue("")
	}
	m.Inputs[InputRateLimit].SetValue(strconv.Itoa(m.Config.RateLimit))
	m.Inputs[InputHeaders].SetValue(strings.Join(m.Config.Headers, ", "))
	m.Inputs[InputBody].SetValue(m.Config.Body)
}

func (m *Ui) calculateLayout() {
	m.layout.headerHeight = 1
	m.layout.requestHeight = 3
	m.layout.configHeight = 6
	m.layout.dashboardHeight = 6
	m.layout.statusHeight = 1

	used := m.layout.headerHeight + m.layout.requestHeight + m.layout.configHeight + m.layout.dashboardHeight + m.layout.statusHeight
	m.layout.responseHeight = m.Height - used
	if m.layout.responseHeight < 5 {
		m.layout.responseHeight = 5
	}
}

func (m *Ui) updateViewportSize() {
	m.ResponseView.Width = m.Width - 4
	m.ResponseView.Height = m.layout.responseHeight - 2
}

func (m *Ui) setFocus(index int) {
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

func (m *Ui) focusNext() {
	next := m.FocusIndex + 1
	if next > NumNonButtonInputs {
		next = 0
	}
	m.setFocus(next)
}

func (m *Ui) focusPrev() {
	prev := m.FocusIndex - 1
	if prev < 0 {
		prev = NumNonButtonInputs
	}
	m.setFocus(prev)
}

func (m Ui) toggleRun() (Ui, tea.Cmd) {
	if m.Running {
		m.stopTest()
		return m, nil
	}
	return m.startTest()
}

func (m Ui) startTest() (Ui, tea.Cmd) {
	targetStr := strings.TrimSpace(m.Inputs[InputURL].Value())
	if targetStr == "" {
		m.StatusMessage = "URL required"
		m.startStatusMessageTimer()
		return m, nil
	}
	targets := strings.Split(targetStr, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}
	m.Config.Targets = targets

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

func (m *Ui) stopTest() {
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

func (m *Ui) updateResponseView() {
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

func (m *Ui) updateMetricsTable(snap MetricsSnapshot) {
	rows := []table.Row{
		{"Reqs", fmt.Sprintf("%d", snap.TotalRequests), getStatusEmoji(snap.SuccessRate)},
		{"Rate", fmt.Sprintf("%.1f%%", snap.SuccessRate), getStatusColor(snap.SuccessRate)},
		{"Lat", fmt.Sprintf("%.0fms", snap.AvgLatencyMs), getLatencyStatus(snap.AvgLatencyMs)},
		{"RPS", fmt.Sprintf("%d", snap.RequestsPerSec), ""},
	}
	m.MetricsTable.SetRows(rows)
}

func (m *Ui) startStatusMessageTimer() {
	if m.StatusMessageTimer != nil {
		m.StatusMessageTimer.Stop()
	}
	m.StatusMessageTimer = time.NewTimer(3 * time.Second)
}

// --- View Rendering ---

func (m Ui) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "Loading..."
	}

	effWidth := m.Width
	if effWidth > 2 {
		effWidth -= 2
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
		return appStyle.Width(m.Width).Height(m.Height).Render(m.renderHelp(effWidth))
	}

	return appStyle.Width(m.Width).Height(m.Height).Render(view)
}

func (m Ui) renderHeader(w int) string {
	title := "OPPOR"
	status := "IDLE"
	if m.Running {
		status = fmt.Sprintf("RUNNING %s", m.Spinner.View())
	}

	return headerStyle.Width(w).Render(lipgloss.JoinHorizontal(lipgloss.Left, title, lipgloss.NewStyle().Align(lipgloss.Right).Width(w-lipgloss.Width(title)-2).Render(status)))
}

func (m Ui) renderRequestBar(w int) string {
	methodW := 35
	btnW := 12

	urlW := w - methodW - btnW - 6
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

func (m Ui) renderSendButton(w int) string {
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

func (m Ui) renderMethodSelector() string {
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

func (m Ui) renderConfigPanel(w int) string {
	colW := (w / 2) - 4
	if colW < 30 {
		colW = w - 4
	}

	renderRow := func(label string, idx int) string {
		l := configLabelStyle.Render(label)
		inW := colW - lipgloss.Width(l) - 2
		if inW < 10 {
			inW = 10
		}

		s := configInputStyle.Width(inW)
		if m.FocusIndex == idx {
			s = configInputFocusedStyle.Width(inW)
		}

		return lipgloss.JoinHorizontal(lipgloss.Left, l, s.Render(m.Inputs[idx].View()))
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

func (m Ui) renderDashboard(w int) string {
	snap := m.Metrics.Snapshot()

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

	if m.Running && m.Config.Requests > 0 {
		m.Progress.Width = w - 20
		prog := lipgloss.NewStyle().PaddingTop(1).Render(m.Progress.View())
		return dashboardStyle.Width(w).Render(lipgloss.JoinVertical(lipgloss.Left, cards, prog))
	}

	return dashboardStyle.Width(w).Render(cards)
}

func (m Ui) renderResponsePanel(w int) string {
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

	border := lipgloss.NewStyle().Width(w).Border(lipgloss.NormalBorder(), false, false, true, false).BorderForeground(borderColor).Render("")

	return lipgloss.JoinVertical(lipgloss.Left,
		tabBar,
		border,
		responsePanelStyle.Width(w).Render(m.ResponseView.View()),
	)
}

func (m Ui) renderMetricsDetail() string {
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

func (m Ui) renderHistogramDetail() string {
	var sb strings.Builder
	sb.WriteString("Latency Distribution:\n\n")
	labels := []string{"<10ms", "10-50ms", "50-100ms", "100-250ms", "250-500ms", "500-1s", "1-2s", "2-5s", "5-10s", ">10s"}
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
		bar := strings.Repeat("█", barLen)
		sb.WriteString(fmt.Sprintf("%-10s %s %d\n", labels[i], bar, val))
	}
	return sb.String()
}

func (m Ui) renderStatusBar(w int) string {
	dur := "0s"
	if m.Running {
		dur = time.Since(m.StartTime).Round(time.Second).String()
	}

	status := m.StatusMessage
	if status == "" {
		status = "Ready"
	}

	left := fmt.Sprintf(" %s | %s", dur, status)
	right := m.Help.ShortHelpView(m.KeyMap.ShortHelp())

	space := w - lipgloss.Width(left) - lipgloss.Width(right)
	if space < 0 {
		space = 0
	}

	return statusBarStyle.Width(w).Render(left + strings.Repeat(" ", space) + right)
}

func (m Ui) renderHelp(w int) string {
	return lipgloss.Place(w, m.Height, lipgloss.Center, lipgloss.Center,
		lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Background(surfaceColor).Padding(1, 2).Render(
			m.Help.FullHelpView(m.KeyMap.FullHelp()),
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
