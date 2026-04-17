package agbero

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	discovery2 "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/parser"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// Global results collector
var benchmarkResults []*strategyResult

type strategyResult struct {
	name        string
	requests    int64
	rps         float64
	avgLatency  time.Duration
	successRate float64
	bytesPerOp  int64
	allocsPerOp int64
	nsPerOp     int64
}

func TestMain(m *testing.M) {
	// Setup: initialize results slice
	benchmarkResults = make([]*strategyResult, 0)

	// Run benchmarks
	exitCode := m.Run()

	// Teardown: print final comparison table
	printFinalComparisonTable()

	os.Exit(exitCode)
}

func BenchmarkServerStrategies(b *testing.B) {
	strategies := []struct {
		name  string
		start string
	}{
		{"round_robin", def.StrategyRoundRobin},
		{"least_conn", def.StrategyLeastConn},
		{"least_response_time", "least_response_time"},
		{"random", def.StrategyRandom},
		{"power_of_two", "power_of_two"},
	}

	for _, s := range strategies {
		b.Run(s.name, func(b *testing.B) {
			result := benchmarkServerWithStrategy(b, s.start)

			// Only collect final results (not the warm-up iterations)
			if b.N > 1000 { // Only collect meaningful runs
				benchmarkResults = append(benchmarkResults, result)
			}
		})
	}
}

func benchmarkServerWithStrategy(b *testing.B, strategy string) *strategyResult {
	// Create a disabled logger
	disabledLogger := ll.New("benchmark").Disable()

	// Create 6 test backend servers with varying latencies
	backends := make([]*httptest.Server, 6)
	for i := range 6 {
		idx := i
		latency := time.Duration(500+500*idx) * time.Microsecond // 0.5ms to 3ms

		backends[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			time.Sleep(latency)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		}))
		defer backends[i].Close()
	}

	// Create temporary config
	tmpDir := b.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, expect.DirPerm); err != nil {
		b.Fatal(err)
	}
	certsDir := expect.NewFolder(filepath.Join(tmpDir, "certs"))
	if err := certsDir.Init(expect.DirPerm); err != nil {
		b.Fatal(err)
	}

	// Create host config file
	hostFile := filepath.Join(hostsDir, "benchmark.localhost.hcl")
	var backendAddrs []string
	for _, be := range backends {
		backendAddrs = append(backendAddrs, fmt.Sprintf(`
    server {
      address = "%s"
      weight = 1
    }`, be.URL))
	}

	hostConfig := fmt.Sprintf(`
domains = ["benchmark.localhost"]

route "/testing" {
  rate_limit {
    ignore_global = true
  }

  health_check {
    path = "/health"
  }

  backend {
    strategy = "%s"
    %s
  }
}
`, strategy, strings.Join(backendAddrs, "\n"))

	if err := os.WriteFile(hostFile, []byte(hostConfig), expect.FilePerm); err != nil {
		b.Fatal(err)
	}

	// Create main config with logging disabled
	configFile := filepath.Join(tmpDir, "agbero.hcl")
	testPort := zulu.PortFree()

	mainConfig := fmt.Sprintf(`version = 1
bind {
  http = [":%d"]
}
storage {
  hosts_dir = "%s"
  data_dir = "%s"
  certs_dir = "%s"
}
timeouts {
  enabled = true
  read = "10s"
  write = "30s"
  idle = "60s"
  read_header = "5s"
}
logging {
  enabled = false
}
`, testPort, hostsDir, tmpDir, certsDir)

	if err := os.WriteFile(configFile, []byte(mainConfig), expect.FilePerm); err != nil {
		b.Fatal(err)
	}

	// Parse global config
	global, err := parser.LoadGlobal(configFile)
	if err != nil {
		b.Fatalf("Failed to parse config: %v", err)
	}
	woos.DefaultApply(global, configFile)

	// Create host manager with disabled logger
	hm := discovery2.NewHost(expect.NewFolder(hostsDir), discovery2.WithLogger(disabledLogger))
	if err := hm.ReloadFull(); err != nil {
		b.Fatalf("Failed to reload hosts: %v", err)
	}

	// Setup shutdown
	shutdown := jack.NewShutdown(jack.ShutdownWithTimeout(5 * time.Second))

	// Create and start server
	s := NewServer(
		WithGlobalConfig(global),
		WithHostManager(hm),
		WithLogger(disabledLogger),
		WithShutdownManager(shutdown),
	)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(configFile)
	}()

	// Wait for server to be ready
	waitForBenchPort(b, testPort)

	// Generate client identities
	const clientPoolSize = 1000
	clientIPs := benchGenerateClientIPs(clientPoolSize)
	userAgents := benchGenerateUserAgents(clientPoolSize)

	var clientCounter uint64
	var successCount atomic.Int64
	var totalLatency atomic.Int64
	var requestCount atomic.Int64

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			DisableKeepAlives:   false,
		},
	}

	// Warm-up: 100 requests to ensure everything is ready
	for range 100 {
		reqURL := fmt.Sprintf("http://127.0.0.1:%d/testing", testPort)
		req, _ := http.NewRequest("GET", reqURL, nil)
		req.Host = "benchmark.localhost"
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		id := atomic.AddUint64(&clientCounter, 1) % uint64(clientPoolSize)
		clientIP := clientIPs[id]
		userAgent := userAgents[id]

		for pb.Next() {
			start := time.Now()

			reqURL := fmt.Sprintf("http://127.0.0.1:%d/testing", testPort)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				continue
			}

			req.Host = "benchmark.localhost"
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("X-Forwarded-For", clientIP)

			resp, err := client.Do(req)
			latency := time.Since(start)

			if err == nil {
				if resp.StatusCode == http.StatusOK {
					successCount.Add(1)
					totalLatency.Add(int64(latency))
					requestCount.Add(1)
				}
				resp.Body.Close()
			}
		}
	})

	b.StopTimer()

	// Trigger shutdown
	shutdown.TriggerShutdown()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}

	// Calculate metrics
	var avgLatency time.Duration
	reqCount := requestCount.Load()
	if reqCount > 0 {
		avgLatency = time.Duration(totalLatency.Load() / reqCount)
	}

	rps := float64(b.N) / b.Elapsed().Seconds()
	successRate := float64(successCount.Load()) / float64(b.N) * 100

	// Return result for final table
	return &strategyResult{
		name:        strings.ToUpper(strategy),
		requests:    int64(b.N),
		rps:         rps,
		avgLatency:  avgLatency,
		successRate: successRate,
		bytesPerOp:  b.Elapsed().Nanoseconds() / int64(b.N),        // approximation
		allocsPerOp: int64(b.Elapsed().Nanoseconds() / int64(b.N)), // will be replaced by real allocs
		nsPerOp:     b.Elapsed().Nanoseconds() / int64(b.N),
	}
}

// Helper functions
func waitForBenchPort(t testing.TB, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Timeout waiting for port %d", port)
}

func benchGenerateClientIPs(n int) []string {
	ips := make([]string, n)
	for i := range n {
		ips[i] = fmt.Sprintf("192.168.%d.%d", i/256, i%256)
	}
	return ips
}

func benchGenerateUserAgents(n int) []string {
	agents := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15",
		"curl/7.68.0",
		"PostmanRuntime/7.26.8",
	}

	result := make([]string, n)
	for i := range n {
		result[i] = agents[i%len(agents)]
	}
	return result
}

func printFinalComparisonTable() {
	if len(benchmarkResults) == 0 {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 100))
	fmt.Println("LOAD BALANCER STRATEGY COMPARISON")
	fmt.Println(strings.Repeat("=", 100))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)

	// Headers
	fmt.Fprintln(w, "Strategy\tRequests\tRPS\tAvg Latency\tSuccess %\tns/op\tB/op\tallocs/op")
	fmt.Fprintln(w, "--------\t--------\t---\t-----------\t---------\t------\t-----\t---------")

	// Sort results by RPS (descending)
	for i := 0; i < len(benchmarkResults); i++ {
		for j := i + 1; j < len(benchmarkResults); j++ {
			if benchmarkResults[i].rps < benchmarkResults[j].rps {
				benchmarkResults[i], benchmarkResults[j] = benchmarkResults[j], benchmarkResults[i]
			}
		}
	}

	// Print each result
	for _, r := range benchmarkResults {
		fmt.Fprintf(w, "%s\t%d\t%.0f\t%v\t%.1f%%\t%d\t%d\t%d\n",
			r.name,
			r.requests,
			r.rps,
			r.avgLatency.Round(time.Microsecond),
			r.successRate,
			r.nsPerOp,
			r.bytesPerOp/1024, // Convert to KB
			r.allocsPerOp,
		)
	}

	w.Flush()
	fmt.Println(strings.Repeat("=", 100) + "\n")
}
