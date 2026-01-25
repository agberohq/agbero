package main

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

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

func fetchAgberoMetrics(url string) tea.Cmd {
	return func() tea.Msg {
		if url == "" {
			return nil
		}

		metrics, err := fetchExternalMetrics(url)
		if err != nil {
			logQueue <- fmt.Sprintf("Failed to fetch Agbero metrics: %v", err)
			return nil
		}

		return agberoMetricsMsg{metrics: metrics}
	}
}
