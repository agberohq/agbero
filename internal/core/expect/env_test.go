package expect

import (
	"os"
	"testing"
)

func TestSplitEnv(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
		wantOk  bool
	}{
		{
			name:    "simple key=value",
			input:   "KEY=value",
			wantKey: "KEY",
			wantVal: "value",
			wantOk:  true,
		},
		{
			name:    "empty value",
			input:   "KEY=",
			wantKey: "KEY",
			wantVal: "",
			wantOk:  true,
		},
		{
			name:    "multiple equals signs",
			input:   "KEY=value=with=equals",
			wantKey: "KEY",
			wantVal: "value=with=equals",
			wantOk:  true,
		},
		{
			name:    "no delimiter",
			input:   "KEYVALUE",
			wantKey: "",
			wantVal: "",
			wantOk:  false,
		},
		{
			name:    "empty string",
			input:   "",
			wantKey: "",
			wantVal: "",
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, val, ok := splitEnv(tt.input)
			if ok != tt.wantOk {
				t.Errorf("splitEnv() ok = %v, want %v", ok, tt.wantOk)
			}
			if key != tt.wantKey {
				t.Errorf("splitEnv() key = %v, want %v", key, tt.wantKey)
			}
			if val != tt.wantVal {
				t.Errorf("splitEnv() val = %v, want %v", val, tt.wantVal)
			}
		})
	}
}

func TestCompileEnv(t *testing.T) {
	// Save original environment and restore after test
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			key, val, _ := splitEnv(env)
			os.Setenv(key, val)
		}
	}()

	// Clear environment for consistent test
	os.Clearenv()
	os.Setenv("SYSTEM_VAR", "system_value")
	os.Setenv("SHARED_VAR", "system_shared")

	globalEnv := map[string]Value{
		"GLOBAL_VAR": Value("global_value"),
		"SHARED_VAR": Value("global_shared"),
	}

	routeEnv := map[string]Value{
		"ROUTE_VAR":  Value("route_value"),
		"SHARED_VAR": Value("route_shared"),
	}

	taskEnv := map[string]Value{
		"TASK_VAR":   Value("task_value"),
		"SHARED_VAR": Value("task_shared"),
	}

	result := CompileEnv(globalEnv, routeEnv, taskEnv)

	// Convert result to map for easier testing
	resultMap := make(map[string]string)
	for _, env := range result {
		key, val, ok := splitEnv(env)
		if ok {
			resultMap[key] = val
		}
	}

	// Check system environment variables are preserved
	if resultMap["SYSTEM_VAR"] != "system_value" {
		t.Errorf("SYSTEM_VAR = %v, want system_value", resultMap["SYSTEM_VAR"])
	}

	// Check that task overrides route overrides global overrides system
	if resultMap["SHARED_VAR"] != "task_shared" {
		t.Errorf("SHARED_VAR = %v, want task_shared", resultMap["SHARED_VAR"])
	}

	// Check global var is present
	if resultMap["GLOBAL_VAR"] != "global_value" {
		t.Errorf("GLOBAL_VAR = %v, want global_value", resultMap["GLOBAL_VAR"])
	}

	// Check route var is present
	if resultMap["ROUTE_VAR"] != "route_value" {
		t.Errorf("ROUTE_VAR = %v, want route_value", resultMap["ROUTE_VAR"])
	}

	// Check task var is present
	if resultMap["TASK_VAR"] != "task_value" {
		t.Errorf("TASK_VAR = %v, want task_value", resultMap["TASK_VAR"])
	}
}

func TestCompileEnvWithResolve(t *testing.T) {
	// Save original environment
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			key, val, _ := splitEnv(env)
			os.Setenv(key, val)
		}
	}()

	os.Clearenv()
	os.Setenv("BASE_VAR", "base_value")
	os.Setenv("REF_VAR", "env.BASE_VAR")

	globalEnv := map[string]Value{
		"RESOLVED_VAR": Value("${BASE_VAR}_suffix"),
	}

	result := CompileEnv(globalEnv, nil, nil)

	resultMap := make(map[string]string)
	for _, env := range result {
		key, val, ok := splitEnv(env)
		if ok {
			resultMap[key] = val
		}
	}

	// Check that environment variables are resolved
	if resultMap["RESOLVED_VAR"] != "base_value_suffix" {
		t.Errorf("RESOLVED_VAR = %v, want base_value_suffix", resultMap["RESOLVED_VAR"])
	}
}

func BenchmarkSplitEnv(b *testing.B) {
	for i := 0; i < b.N; i++ {
		splitEnv("KEY=value")
	}
}

func BenchmarkCompileEnv(b *testing.B) {
	globalEnv := map[string]Value{
		"GLOBAL_VAR": Value("global_value"),
	}
	routeEnv := map[string]Value{
		"ROUTE_VAR": Value("route_value"),
	}
	taskEnv := map[string]Value{
		"TASK_VAR": Value("task_value"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CompileEnv(globalEnv, routeEnv, taskEnv)
	}
}
