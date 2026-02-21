package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

var titleStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#7D56F4")).
	MarginTop(1).
	MarginBottom(1)

func runInteractive() {
	fmt.Println(titleStyle.Render("⚡ Oppor - Load Balancer Testing Tool"))

	var mode string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Mode").
				Options(
					huh.NewOption("🚀 Load Test", "load"),
					huh.NewOption("🖥️  Server Mode", "server"),
				).
				Value(&mode),
		),
	)

	if err := form.Run(); err != nil {
		fmt.Println("Error:", err)
		return
	}

	if mode == "load" {
		runInteractiveLoadTest()
	} else {
		runInteractiveServer()
	}
}

func runInteractiveLoadTest() {
	var targets string
	var concurrencyStr string
	var requestsStr string
	var duration string
	var rateLimitStr string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Target URLs (comma separated)").
				Placeholder("http://localhost:8080,http://localhost:8081").
				Value(&targets).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("at least one target required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Concurrency (workers)").
				Placeholder("10").
				Value(&concurrencyStr).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					_, err := strconv.Atoi(s)
					return err
				}),

			huh.NewInput().
				Title("Total Requests (0 = infinite)").
				Placeholder("1000").
				Value(&requestsStr).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					_, err := strconv.Atoi(s)
					return err
				}),

			huh.NewInput().
				Title("Duration (e.g. 30s, 5m, leave empty for request limit)").
				Placeholder("30s").
				Value(&duration),

			huh.NewInput().
				Title("Rate Limit (req/sec, 0 = unlimited)").
				Placeholder("0").
				Value(&rateLimitStr).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					_, err := strconv.Atoi(s)
					return err
				}),
		),
	)

	if err := form.Run(); err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Parse values with defaults
	concurrency := 10
	if concurrencyStr != "" {
		if v, err := strconv.Atoi(concurrencyStr); err == nil {
			concurrency = v
		}
	}

	requests := 1000
	if requestsStr != "" {
		if v, err := strconv.Atoi(requestsStr); err == nil {
			requests = v
		}
	}

	rateLimit := 0
	if rateLimitStr != "" {
		if v, err := strconv.Atoi(rateLimitStr); err == nil {
			rateLimit = v
		}
	}

	dur, _ := time.ParseDuration(duration)
	cfg := LoadConfig{
		Targets:     strings.Split(targets, ","),
		Concurrency: concurrency,
		Requests:    requests,
		Duration:    dur,
		RateLimit:   rateLimit,
		Method:      "GET",
	}

	runLoadTest(cfg)
}

func runInteractiveServer() {
	var port string
	var speed string
	var failureRateStr string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Port").
				Placeholder("8080").
				Value(&port),

			huh.NewSelect[string]().
				Title("Speed Profile").
				Options(
					huh.NewOption("Fast (1ms)", "fast"),
					huh.NewOption("Normal (10ms)", "normal"),
					huh.NewOption("Slow (100ms)", "slow"),
					huh.NewOption("Erratic (variable)", "erratic"),
				).
				Value(&speed),

			huh.NewInput().
				Title("Failure Rate (0.0 - 1.0)").
				Placeholder("0").
				Value(&failureRateStr),
		),
	)

	if err := form.Run(); err != nil {
		fmt.Println("Error:", err)
		return
	}

	if port == "" {
		port = "8080"
	}

	failureRate := 0.0
	if failureRateStr != "" {
		if v, err := strconv.ParseFloat(failureRateStr, 64); err == nil {
			failureRate = v
		}
	}

	cfg := ServerConfig{
		Port:        port,
		Speed:       speed,
		FailureRate: failureRate,
	}

	if err := runServer(cfg); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
