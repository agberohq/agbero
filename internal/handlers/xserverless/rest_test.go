package xserverless

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
)

const (
	testHeaderKey    = "X-Test-Header"
	testHeaderVal    = "TestValue"
	testQueryKey     = "q"
	testEnvKey       = "MY_VAR"
	testEnvVal       = "resolved-env"
	testUpstreamPath = "/upstream"
	testTimeout      = 2 * time.Second
)

// TestNewRest verifies that the REST handler is correctly initialized with defaults.
// It checks that the internal HTTP client is configured with the expected timeout.
func TestNewRest(t *testing.T) {
	res := resource.New()
	cfg := alaye.REST{
		URL:     "http://localhost",
		Timeout: alaye.Duration(testTimeout),
	}

	handler := NewRest(RestConfig{
		Resource: res,
		REST:     cfg,
	})

	if handler.client.Timeout != testTimeout {
		t.Errorf("expected timeout %v, got %v", testTimeout, handler.client.Timeout)
	}

	cfgNoTimeout := alaye.REST{URL: "http://localhost"}
	handlerDefault := NewRest(RestConfig{
		Resource: res,
		REST:     cfgNoTimeout,
	})

	if handlerDefault.client.Timeout != defaultRESTTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultRESTTimeout, handlerDefault.client.Timeout)
	}
}

// TestRestServeHTTP validates the end-to-end request flow for serverless REST proxying.
// It simulates an upstream server and verifies that headers, queries, and bodies are handled.
func TestRestServeHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testHeaderKey) != testHeaderVal {
			t.Errorf("missing header in upstream request")
		}
		if r.URL.Query().Get(testQueryKey) != testEnvVal {
			t.Errorf("expected resolved query param %s, got %s", testEnvVal, r.URL.Query().Get(testQueryKey))
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer ts.Close()

	res := resource.New()
	cfg := alaye.REST{
		URL:    ts.URL + testUpstreamPath,
		Method: http.MethodPost,
		Headers: map[string]string{
			testHeaderKey: testHeaderVal,
		},
		Query: map[string]alaye.Value{
			testQueryKey: alaye.Value("env." + testEnvKey),
		},
	}

	handler := NewRest(RestConfig{
		Resource: res,
		REST:     cfg,
		GlobalEnv: map[string]alaye.Value{
			testEnvKey: alaye.Value(testEnvVal),
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rr.Code)
	}
	if rr.Body.String() != "created" {
		t.Errorf("expected body 'created', got '%s'", rr.Body.String())
	}
}

// TestRestErrors ensures that the handler gracefully manages invalid configurations and network failures.
// It covers invalid target URLs and unreachable upstream services.
func TestRestErrors(t *testing.T) {
	res := resource.New()

	t.Run("InvalidURL", func(t *testing.T) {
		handler := NewRest(RestConfig{
			Resource: res,
			REST:     alaye.REST{URL: "%%invalid-url"},
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected 500 for invalid URL, got %d", rr.Code)
		}
	})

	t.Run("UpstreamFailure", func(t *testing.T) {
		handler := NewRest(RestConfig{
			Resource: res,
			REST:     alaye.REST{URL: "http://unreachable.local", Method: http.MethodGet},
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Errorf("expected 502 for unreachable upstream, got %d", rr.Code)
		}
	})
}
