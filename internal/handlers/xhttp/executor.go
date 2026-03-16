package xhttp

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type HTTPExecutor struct {
	URL            string
	Method         string
	Client         *http.Client
	Header         http.Header
	Host           string
	ExpectedStatus []int
	ExpectedBody   string
}

func (h *HTTPExecutor) Probe(ctx context.Context) (bool, time.Duration, error) {
	start := time.Now()

	method := h.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, h.URL, nil)
	if err != nil {
		return false, time.Since(start), err
	}

	if h.Host != "" {
		req.Host = h.Host
	}
	if len(h.Header) > 0 {
		req.Header = h.Header.Clone()
	}

	resp, err := h.Client.Do(req)
	latency := time.Since(start)

	if err != nil {
		return false, latency, err
	}
	defer resp.Body.Close()

	// Determine success based on status code
	success := false
	if len(h.ExpectedStatus) > 0 {
		// If ExpectedStatus is configured, only those codes are success
		if slices.Contains(h.ExpectedStatus, resp.StatusCode) {
			success = true
		}
	} else {
		// Default: 2xx-4xx = healthy (server responded); 5xx = unhealthy
		// Rationale: 4xx indicates client error (resource/auth issue), not server failure.
		// Load balancer should keep routing to servers that respond, even with 4xx.
		success = resp.StatusCode >= 200 && resp.StatusCode < 500
	}

	// If status matched and ExpectedBody is set, verify body content
	if success && h.ExpectedBody != "" {
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 10240))
		if readErr != nil {
			// Body read failure: treat as probe failure, but connection still drained
			success = false
		} else if !strings.Contains(string(bodyBytes), h.ExpectedBody) {
			success = false
		}
	}

	// ALWAYS drain remaining body to enable HTTP connection reuse.
	// This is critical for high-frequency health checks to avoid connection leaks.
	io.Copy(io.Discard, resp.Body)

	return success, latency, nil
}
