// cmd/oppor/main.go
package main

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/integrii/flaggy"
	"github.com/olekukonko/ll"
)

var logger = ll.New("opopo", ll.WithFatalExits(true))
var logQueue = make(chan string, 1000)

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

	serveMode  bool
	portString string
	startPort  int
	endPort    int
	totalPorts int
)

func main() {
	flaggy.SetName("oppor")
	flaggy.SetDescription("Interactive Load Tester")
	flaggy.SetVersion("3.0.0")

	// Server Subcommand
	serveCmd := flaggy.NewSubcommand("serve")
	serveCmd.String(&portString, "p", "port", "Comma-separated ports")
	serveCmd.Int(&startPort, "s", "start", "Start port")
	serveCmd.Int(&endPort, "e", "end", "End port")
	serveCmd.Int(&totalPorts, "P", "total", "Total ports")
	flaggy.AttachSubcommand(serveCmd, 1)

	// Load Test Flags (Defaults for the UI)
	flaggy.StringSlice(&targets, "t", "target", "Target URLs")
	flaggy.Int(&concurrency, "c", "concurrency", "Workers (default: 10)")
	flaggy.Int(&requests, "n", "requests", "Total requests")
	flaggy.String(&duration, "d", "duration", "Duration")
	flaggy.Int(&rateLimit, "r", "rate", "Rate limit")
	flaggy.String(&method, "X", "method", "Method")
	flaggy.Bool(&verbose, "v", "verbose", "Verbose logging")

	flaggy.Parse()

	if serveCmd.Used {
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

	var dur time.Duration
	if duration != "" {
		dur, _ = time.ParseDuration(duration)
	}

	if concurrency <= 0 {
		concurrency = 10
	}
	if method == "" {
		method = "GET"
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
		KeepAlive:   true,
		Timeout:     30 * time.Second,
		Verbose:     verbose,
	}

	// Initialize Ui in Config State
	model := NewModel(config)

	p := tea.NewProgram(&model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
