package upstream

import (
	"context"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/jack"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Address:  "http://example.com",
				Resource: resource.New(),
			},
			wantErr: false,
		},
		{
			name: "empty address",
			cfg: Config{
				Address:  "",
				Resource: resource.New(),
			},
			wantErr: true,
		},
		{
			name: "nil resource",
			cfg: Config{
				Address:  "http://example.com",
				Resource: nil,
			},
			wantErr: true,
		},
		{
			name: "resource missing metrics",
			cfg: Config{
				Address: "http://example.com",
				Resource: func() *resource.Manager {
					r := resource.New()
					r.Metrics = nil
					return r
				}(),
			},
			wantErr: true,
		},
		{
			name: "resource missing health",
			cfg: Config{
				Address: "http://example.com",
				Resource: func() *resource.Manager {
					r := resource.New()
					r.Health = nil
					return r
				}(),
			},
			wantErr: true,
		},
		{
			name: "resource missing doctor",
			cfg: Config{
				Address:   "http://example.com",
				HasProber: true,
				Resource: func() *resource.Manager {
					r := resource.New()
					r.Doctor = nil
					return r
				}(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewBase_InvalidConfig(t *testing.T) {
	cfg := Config{
		Address:  "",
		Resource: resource.New(),
	}
	_, err := NewBase(cfg)
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}

func TestNewBase_DefaultWeight(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Weight:   0,
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	if base.WeightVal != 1 {
		t.Errorf("Expected default weight 1, got %d", base.WeightVal)
	}
}

func TestBase_Status_Down(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:     "http://example.com",
		CBThreshold: 2,
		Resource:    res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Status(false)
	if base.HealthScore.Status() != health.StatusUnhealthy {
		t.Errorf("Expected unhealthy status, got %v", base.HealthScore.Status())
	}
	if base.Activity.Failures.Load() < uint64(base.CBThreshold+1) {
		t.Error("Expected failures to be set above threshold")
	}
}

func TestBase_Status_Up(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Status(false)
	base.Status(true)
	if base.HealthScore.Status() != health.StatusHealthy {
		t.Errorf("Expected healthy status, got %v", base.HealthScore.Status())
	}
	if base.Activity.Failures.Load() != 0 {
		t.Error("Expected failures to be reset to 0")
	}
}

func TestBase_Alive_CircuitBreaker(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:     "http://example.com",
		CBThreshold: 2,
		Resource:    res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Activity.Failures.Store(3)
	if base.Alive() {
		t.Error("Expected base to be dead when failures exceed threshold")
	}
}

func TestBase_Alive_HealthScore(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:   "http://example.com",
		HasProber: true,
		Resource:  res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.HealthScore.Update(health.Record{
		ProbeSuccess: false,
		ConnHealth:   0,
	})
	if base.Alive() {
		t.Error("Expected base to be dead when health score is unhealthy")
	}
}

func TestBase_Alive_NoProber(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:   "http://example.com",
		HasProber: false,
		Resource:  res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	if !base.Alive() {
		t.Error("Expected base to be alive when no prober is configured")
	}
}

func TestBase_IsUsable_MaxConns(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:        "http://example.com",
		MaxConnections: 1,
		Resource:       res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Activity.StartRequest()
	if base.IsUsable() {
		t.Error("Expected base to be unusable when max connections reached")
	}
}

func TestBase_IsUsable_NotAlive(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Status(false)
	if base.IsUsable() {
		t.Error("Expected base to be unusable when not alive")
	}
}

func TestBase_Weight_HealthAdjusted(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Weight:   10,
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.HealthScore.Update(health.Record{
		ProbeSuccess: false,
		ConnHealth:   50,
	})
	weight := base.Weight()
	if weight >= 10 {
		t.Errorf("Expected weight to be reduced due to health, got %d", weight)
	}
}

func TestBase_Weight_NoHealthScore(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Weight:   10,
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.HealthScore = nil
	weight := base.Weight()
	if weight != 10 {
		t.Errorf("Expected weight 10 when no health score, got %d", weight)
	}
}

func TestBase_InFlight(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Activity.StartRequest()
	base.Activity.StartRequest()
	if base.InFlight() != 2 {
		t.Errorf("Expected in-flight 2, got %d", base.InFlight())
	}
}

func TestBase_ResponseTime_NoData(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	rt := base.ResponseTime()
	if rt != 0 {
		t.Errorf("Expected response time 0 with no data, got %d", rt)
	}
}

func TestBase_ResponseTime_WithData(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Activity.EndRequest(100, false)
	base.Activity.EndRequest(200, false)
	base.Activity.EndRequest(300, false)
	rt := base.ResponseTime()
	if rt == 0 {
		t.Error("Expected non-zero response time with data")
	}
}

func TestBase_OnDialFailure(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.OnDialFailure(nil)
	if base.Activity.Failures.Load() != 1 {
		t.Errorf("Expected failures to be 1, got %d", base.Activity.Failures.Load())
	}
}

func TestBase_Uptime(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	uptime := base.Uptime()
	if uptime < 10*time.Millisecond {
		t.Errorf("Expected uptime >= 10ms, got %v", uptime)
	}
}

func TestBase_LastRecovery(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	recovery := base.LastRecovery()
	if recovery.IsZero() {
		t.Error("Expected non-zero last recovery time")
	}
}

func TestBase_RegisterHealth_NoProber(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:   "http://example.com",
		HasProber: false,
		Resource:  res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	err = base.RegisterHealth(health.ProbeConfig{}, nil, nil)
	if err != nil {
		t.Errorf("RegisterHealth() error = %v", err)
	}
}

func TestBase_RegisterHealth_Success(t *testing.T) {
	res := resource.New()
	res.Doctor = jack.NewDoctor()
	defer res.Doctor.StopAll(1 * time.Second)
	cfg := Config{
		Address:   "http://example.com",
		HasProber: true,
		Resource:  res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	probeCfg := health.ProbeConfig{
		StandardInterval: 100 * time.Millisecond,
		Timeout:          50 * time.Millisecond,
	}
	checkFn := func(ctx context.Context) error {
		return nil
	}
	err = base.RegisterHealth(probeCfg, checkFn, nil)
	if err != nil {
		t.Errorf("RegisterHealth() error = %v", err)
	}
}

func TestBase_RegisterHealth_NilDoctor(t *testing.T) {
	res := resource.New()
	res.Doctor = nil
	cfg := Config{
		Address:   "http://example.com",
		HasProber: true,
		Resource:  res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	err = base.RegisterHealth(health.ProbeConfig{}, nil, nil)
	if err == nil {
		t.Error("Expected error for nil doctor")
	}
}

func TestBase_ConcurrentOperations(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	done := make(chan bool, 10)
	for range 10 {
		go func() {
			base.Status(true)
			base.Status(false)
			base.Alive()
			base.Weight()
			base.InFlight()
			done <- true
		}()
	}
	for range 10 {
		<-done
	}
}

func TestBase_MetricsRecording(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.Activity.StartRequest()
	time.Sleep(10 * time.Millisecond)
	base.Activity.EndRequest(100, false)
	snap := base.Activity.Snapshot()
	if snap["requests"].(uint64) != 1 {
		t.Errorf("Expected 1 request, got %v", snap["requests"])
	}
	if snap["failures"].(uint64) != 0 {
		t.Errorf("Expected 0 failures, got %v", snap["failures"])
	}
}

func TestBase_HealthScoreUpdate(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.HealthScore.Update(health.Record{
		ProbeLatency: 50 * time.Millisecond,
		ProbeSuccess: true,
		ConnHealth:   100,
		PassiveRate:  0,
	})
	if base.HealthScore.Value() < 90 {
		t.Errorf("Expected health score >= 90, got %d", base.HealthScore.Value())
	}
}

func TestBase_PassiveRequestRecording(t *testing.T) {
	res := resource.New()
	cfg := Config{
		Address:  "http://example.com",
		Resource: res,
	}
	base, err := NewBase(cfg)
	if err != nil {
		t.Fatalf("NewBase() error = %v", err)
	}
	base.HealthScore.RecordPassiveRequest(true)
	base.HealthScore.RecordPassiveRequest(true)
	base.HealthScore.RecordPassiveRequest(false)
	rate := base.HealthScore.PassiveErrorRate()
	if rate < 0.3 || rate > 0.4 {
		t.Errorf("Expected passive error rate ~0.33, got %f", rate)
	}
}
