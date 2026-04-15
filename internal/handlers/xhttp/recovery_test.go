package xhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

func newTestResource(t *testing.T) *resource.Resource {
	t.Helper()
	res := resource.New()
	t.Cleanup(func() { res.Close() })
	return res
}

func newTestBackend(t *testing.T, srv *httptest.Server, cbThreshold int64, healthPath string) *Backend {
	t.Helper()
	res := newTestResource(t)

	route := &alaye.Route{Path: "/"}
	if healthPath != "" {
		route.HealthCheck = alaye.HealthCheck{Path: healthPath}
	}

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.Server{Address: alaye.Address(srv.URL)},
		Route:    route,
		Domains:  []string{"test.localhost"},
		Resource: res,
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	if cbThreshold > 0 {
		b.CBThreshold = cbThreshold
	}
	t.Cleanup(func() { b.Stop() })
	return b
}

// tripCircuit drives the failure counter to CBThreshold using OnDialFailure.
// The circuit breaker counts dial-level failures, not HTTP 5xx responses.
// A 5xx from an upstream is a successful proxy operation from httputil's
// perspective — only a connection-refused or similar dial error increments
// the Failures counter and can trip the breaker.
func tripCircuit(b *Backend) {
	for i := int64(0); i < b.CBThreshold; i++ {
		b.OnDialFailure(fmt.Errorf("simulated dial failure %d", i))
	}
}

// hammer sends n GET requests through b.ServeHTTP and returns the 5xx count.
func hammer(b *Backend, n int) (failures int) {
	for range n {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, req)
		if w.Code >= 500 {
			failures++
		}
	}
	return
}

// waitUsable polls IsUsable() until true or timeout.
func waitUsable(b *Backend, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b.IsUsable() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// TestCircuitBreaker_StunLock reproduces the death spiral where
// RecordResult(false) kept resetting LastRecov on every failure, preventing
// the half-open window from ever opening.
//
// The breaker counts dial failures (OnDialFailure), not 5xx responses.
// We trip it via OnDialFailure, then keep calling OnDialFailure for 3 s
// to simulate the stun-lock flood, then verify recovery after silence.
//
//	BEFORE fix: IsUsable() stays false — LastRecov resets on every
//	            OnDialFailure, pushing the 5s cooldown into the future forever.
//	AFTER  fix: IsUsable() returns true within DefaultHalfOpenCooldown + buffer.
func TestCircuitBreaker_StunLock(t *testing.T) {
	const cbThreshold = int64(5)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	b := newTestBackend(t, srv, cbThreshold, "")

	tripCircuit(b)

	if b.IsUsable() {
		t.Fatalf(
			"pre-condition: circuit should be open after %d dial failures, IsUsable() returned true\n"+
				"Failures=%d CBThreshold=%d",
			cbThreshold, b.Activity.Failures.Load(), b.CBThreshold,
		)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				b.OnDialFailure(fmt.Errorf("sustained dial failure"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	})
	time.Sleep(3 * time.Second)
	close(stop)
	wg.Wait()

	const waitBudget = 8 * time.Second
	if !waitUsable(b, waitBudget) {
		t.Fatalf(
			"circuit never recovered after %s of silence\n"+
				"LastRecov is likely being reset on every failure (Bug 1)\n"+
				"Failures=%d LastRecov=%v",
			waitBudget,
			b.Activity.Failures.Load(),
			time.Unix(0, b.LastRecov.Load()),
		)
	}
}

// TestCircuitBreaker_HalfOpenAllowsOneProbe verifies the half-open window:
// after the cooldown elapses, AcquireCircuit grants a probe, and a successful
// RecordResult(true) closes the circuit cleanly.
func TestCircuitBreaker_HalfOpenAllowsOneProbe(t *testing.T) {
	const cbThreshold = int64(3)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	b := newTestBackend(t, srv, cbThreshold, "")

	// Place backend in tripped state with an already-expired cooldown.
	b.Activity.Failures.Store(uint64(cbThreshold))
	b.LastRecov.Store(time.Now().Add(-10 * time.Second).UnixNano())

	if !b.AcquireCircuit() {
		t.Fatal("expected AcquireCircuit to return true in half-open state")
	}

	b.RecordResult(true)

	if b.Activity.Failures.Load() != 0 {
		t.Fatalf("expected Failures=0 after successful probe, got %d",
			b.Activity.Failures.Load())
	}
	if !b.IsUsable() {
		t.Fatal("expected backend to be usable after successful recovery")
	}
}

// TestRecordResult_DoesNotResetLastRecovOnFailure verifies that RecordResult(false)
// after the circuit has tripped does not push LastRecov forward.
func TestRecordResult_DoesNotResetLastRecovOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	b := newTestBackend(t, srv, 5, "")

	// Trip the circuit and capture the trip timestamp.
	tripCircuit(b)
	tripTime := time.Unix(0, b.LastRecov.Load())

	// Subsequent RecordResult(false) calls must not move LastRecov.
	for range 10 {
		b.RecordResult(false)
		time.Sleep(10 * time.Millisecond)
	}

	stored := time.Unix(0, b.LastRecov.Load())
	drift := stored.Sub(tripTime)
	if drift < 0 {
		drift = -drift
	}
	if drift > 100*time.Millisecond {
		t.Fatalf(
			"RecordResult(false) updated LastRecov after trip:\n"+
				"  trip=%v\n  stored=%v\n  drift=%v\n"+
				"Bug 1: LastRecov must only be written when the circuit first trips",
			tripTime.Format(time.RFC3339Nano),
			stored.Format(time.RFC3339Nano),
			drift,
		)
	}
}

// TestPassiveRate_LifetimePoisoning reproduces the score poisoning where
// passiveErrors/passiveRequests accumulated forever and prevented recovery.
func TestPassiveRate_LifetimePoisoning(t *testing.T) {
	score := health.NewScore(
		health.DefaultThresholds(),
		health.DefaultScoringWeights(),
		health.DefaultLatencyThresholds(),
		nil,
	)

	const total = 1_000_000
	const errorRate = 0.083
	errCount := int(total * errorRate)

	for range errCount {
		score.RecordPassiveRequest(false)
	}
	for i := 0; i < total-errCount; i++ {
		score.RecordPassiveRequest(true)
	}

	rateBefore := score.PassiveErrorRate()
	if rateBefore < 0.05 {
		t.Fatalf("pre-condition: expected passive error rate ~8%%, got %.4f", rateBefore)
	}

	score.Update(health.Record{
		ProbeLatency: 5 * time.Millisecond,
		ProbeSuccess: true,
		ConnHealth:   100,
		PassiveRate:  score.PassiveErrorRate(),
	})

	rateAfter := score.PassiveErrorRate()
	if rateAfter > 0.01 {
		t.Fatalf(
			"passive error rate not reset by Score.Update(): before=%.4f after=%.4f\n"+
				"Bug 2: lifetime counters permanently poison the health score",
			rateBefore, rateAfter,
		)
	}
	if state := score.State(); state != health.StateHealthy {
		t.Fatalf("expected StateHealthy after clean probe, got %s (score=%d)",
			state, score.Value())
	}
}

// TestPassiveRate_ResetsEachProbeCycle verifies that consecutive probe cycles
// each measure only their own window, not lifetime totals.
func TestPassiveRate_ResetsEachProbeCycle(t *testing.T) {
	score := health.NewScore(
		health.DefaultThresholds(),
		health.DefaultScoringWeights(),
		health.DefaultLatencyThresholds(),
		nil,
	)

	// Window 1: 50% error rate.
	for i := range 100 {
		score.RecordPassiveRequest(i%2 == 0)
	}
	score.Update(health.Record{
		ProbeSuccess: true,
		ConnHealth:   100,
		PassiveRate:  score.PassiveErrorRate(),
	})

	// Window 2: 0% error rate.
	for range 100 {
		score.RecordPassiveRequest(true)
	}

	rateAfterCleanWindow := score.PassiveErrorRate()
	// With fix: reflects window 2 only (~0%).
	// Without fix: lifetime = 25% (50 errors / 200 total).
	if rateAfterCleanWindow > 0.05 {
		t.Fatalf(
			"passive error rate carried over from previous window: got %.4f, want ~0\n"+
				"Score.Update() must reset passiveErrors and passiveRequests (Bug 2 fix)",
			rateAfterCleanWindow,
		)
	}
}

// TestDeathSpiral_FullRecovery mirrors the production scenario:
// oppor serve -f 0.1 -fp burst + hey -n 1000000.
//
// We close the server to generate real dial failures that trip the circuit,
// then restart it on the same address so the health probe can reach it,
// and verify recovery within 3 probe intervals via the real jack.Doctor.
func TestDeathSpiral_FullRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping death-spiral integration test in short mode")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := httptest.NewServer(mux)
	srvAddr := srv.Listener.Addr().String()

	res := newTestResource(t)
	route := &alaye.Route{
		Path: "/",
		HealthCheck: alaye.HealthCheck{
			Path:     "/health",
			Interval: alaye.Duration(2 * time.Second),
			Timeout:  alaye.Duration(time.Second),
		},
	}

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.Server{Address: alaye.Address(srv.URL)},
		Route:    route,
		Domains:  []string{"test.localhost"},
		Resource: res,
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	if !b.IsUsable() {
		t.Fatal("phase 1: backend should be usable before burst")
	}

	t.Log("phase 2: closing server, tripping circuit")
	srv.Close()
	tripCircuit(b)

	if b.IsUsable() {
		t.Logf("note: circuit did not trip — CBThreshold=%d may exceed tripCircuit volume",
			b.CBThreshold)
	} else {
		t.Logf("phase 2: circuit tripped — Failures=%d CBThreshold=%d",
			b.Activity.Failures.Load(), b.CBThreshold)
	}

	listener, err := net.Listen("tcp", srvAddr)
	if err != nil {
		t.Fatalf("could not re-listen on %s: %v", srvAddr, err)
	}
	newSrv := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: mux},
	}
	newSrv.Start()
	defer newSrv.Close()

	t.Log("phase 3: server back online, waiting for recovery")

	const recoveryBudget = 3 * 2 * time.Second
	if !waitUsable(b, recoveryBudget) {
		t.Fatalf(
			"backend did not recover within %s\n"+
				"Failures=%d  Score=%d  State=%s\n"+
				"Check RecordResult + PassiveErrorRate fixes",
			recoveryBudget,
			b.Activity.Failures.Load(),
			b.HealthScore.Value(),
			b.HealthScore.State(),
		)
	}

	t.Logf("phase 3: recovered — score=%d state=%s failures=%d",
		b.HealthScore.Value(), b.HealthScore.State(), b.Activity.Failures.Load())

	failures := hammer(b, 100)
	if failures > 0 {
		t.Fatalf("phase 4: expected 0 failures after recovery, got %d/100", failures)
	}
	t.Log("phase 4: normal traffic flowing cleanly")
}

// BenchmarkBackend_HealthyThroughput establishes the per-request overhead on
// a healthy backend.
//
// Save output with `tee bench_baseline.txt`. A >20% regression in ns/op after
// any refactor touching ServeHTTP → ReverseProxy warrants investigation.
func BenchmarkBackend_HealthyThroughput(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	res := resource.New()
	defer res.Close()

	be, err := NewBackend(ConfigBackend{
		Server:   alaye.Server{Address: alaye.Address(srv.URL)},
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{"bench.localhost"},
		Resource: res,
	})
	if err != nil {
		b.Fatalf("NewBackend: %v", err)
	}
	defer be.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			be.ServeHTTP(w, req)
		}
	})
}

// BenchmarkBackend_CircuitBreakerCheck measures IsUsable() overhead — the
// hot path called on every request pick by the load balancer.
func BenchmarkBackend_CircuitBreakerCheck(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	res := resource.New()
	defer res.Close()

	be, _ := NewBackend(ConfigBackend{
		Server:   alaye.Server{Address: alaye.Address(srv.URL)},
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{"bench.localhost"},
		Resource: res,
	})
	defer be.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = be.IsUsable()
		}
	})
}

func newTestActivity() *metrics.Activity { return &metrics.Activity{} }

func forceProbe(ctx context.Context, b *Backend) error {
	if !b.HasProber {
		return nil
	}
	executor := &HTTPExecutor{
		URL:    b.Address + b.hcConfig.Path,
		Method: "GET",
		Client: http.DefaultClient,
	}
	success, latency, err := executor.Probe(ctx)
	b.HealthScore.Update(health.Record{
		ProbeLatency: latency,
		ProbeSuccess: success,
		ConnHealth:   100,
		PassiveRate:  b.HealthScore.PassiveErrorRate(),
	})
	return err
}

// Ensure atomic.Bool import is used — needed by TestCircuitBreaker_StunLock
// indirectly via the closure.
var _ atomic.Bool
