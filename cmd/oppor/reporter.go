package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type Reporter struct {
	Metrics *LoadMetrics
	Config  LoadConfig
}

func NewReporter(metrics *LoadMetrics, cfg LoadConfig) *Reporter {
	return &Reporter{Metrics: metrics, Config: cfg}
}

func (r *Reporter) PrintSummary() {
	snap := r.Metrics.Snapshot()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("                    LOAD TEST RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\n📊 Configuration:\n")
	fmt.Printf("  Targets:      %v\n", r.Config.Targets)
	fmt.Printf("  Concurrency:  %d workers\n", r.Config.Concurrency)
	fmt.Printf("  Duration:     %.2fs\n", snap["elapsed"])

	fmt.Printf("\n📈 Requests:\n")
	fmt.Printf("  Total:        %d\n", snap["total"])
	fmt.Printf("  Successful:   %d (%.2f%%)\n", snap["success"], snap["success_rate"])
	fmt.Printf("  Errors:       %d\n", snap["errors"])
	fmt.Printf("  RPS:          %.2f req/sec\n", snap["rps"])

	fmt.Printf("\n⏱️  Latency:\n")
	fmt.Printf("  Average:      %.2f ms\n", snap["latency_avg"])
	fmt.Printf("  P50:          %.2f ms\n", snap["latency_p50"])
	fmt.Printf("  P95:          %.2f ms\n", snap["latency_p95"])
	fmt.Printf("  P99:          %.2f ms\n", snap["latency_p99"])
	fmt.Printf("  Std Dev:      %.2f ms\n", snap["latency_std"])

	fmt.Printf("\n📦 Data:\n")
	fmt.Printf("  Total:        %s\n", snap["bytes_human"])

	if codes, ok := snap["status_codes"].(map[string]uint64); ok && len(codes) > 0 {
		fmt.Printf("\n🔢 Status Codes:\n")
		var keys []string
		for k := range codes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s: %d\n", k, codes[k])
		}
	}

	if errors, ok := snap["error_types"].(map[string]uint64); ok && len(errors) > 0 {
		fmt.Printf("\n❌ Error Types:\n")
		var keys []string
		for k := range errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s: %d\n", k, errors[k])
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
}

func (r *Reporter) ExportJSON(filename string) error {
	snap := r.Metrics.Snapshot()
	data := map[string]interface{}{
		"config": map[string]interface{}{
			"targets":     r.Config.Targets,
			"concurrency": r.Config.Concurrency,
			"requests":    r.Config.Requests,
			"duration":    r.Config.Duration.Seconds(),
		},
		"results":    snap,
		"timeseries": r.Metrics.GetPerSecond(),
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (r *Reporter) ExportCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"timestamp", "total_requests", "errors", "bytes", "rps"})

	// Write per-second data
	perSecond := r.Metrics.GetPerSecond()
	var prev *SecondMetrics
	for _, sec := range perSecond {
		rps := uint64(0)
		errors := sec.Errors
		bytes := sec.Bytes
		if prev != nil {
			rps = sec.Requests - prev.Requests
			errors = sec.Errors - prev.Errors
			bytes = sec.Bytes - prev.Bytes
		}
		writer.Write([]string{
			sec.Timestamp.Format(time.RFC3339),
			fmt.Sprintf("%d", sec.Requests),
			fmt.Sprintf("%d", errors),
			fmt.Sprintf("%d", bytes),
			fmt.Sprintf("%d", rps),
		})
		prev = &sec
	}

	return nil
}

func runLoadTest(cfg LoadConfig) {
	fmt.Printf("Starting load test with %d workers", cfg.Concurrency)
	if cfg.Requests > 0 {
		fmt.Printf(", %d requests", cfg.Requests)
	}
	if cfg.Duration > 0 {
		fmt.Printf(", duration %v", cfg.Duration)
	}
	if cfg.RateLimit > 0 {
		fmt.Printf(", rate limit %d req/s", cfg.RateLimit)
	}
	fmt.Println()

	tester := NewLoad(cfg)
	metrics := tester.Run()

	reporter := NewReporter(metrics, cfg)
	reporter.PrintSummary()

	// Auto-export results
	timestamp := time.Now().Format("20060102-150405")
	jsonFile := fmt.Sprintf("loadtest-%s.json", timestamp)
	csvFile := fmt.Sprintf("loadtest-%s.csv", timestamp)

	if err := reporter.ExportJSON(jsonFile); err != nil {
		fmt.Printf("Warning: failed to export JSON: %v\n", err)
	} else {
		fmt.Printf("Results exported to %s\n", jsonFile)
	}

	if err := reporter.ExportCSV(csvFile); err != nil {
		fmt.Printf("Warning: failed to export CSV: %v\n", err)
	} else {
		fmt.Printf("Timeseries exported to %s\n", csvFile)
	}
}
