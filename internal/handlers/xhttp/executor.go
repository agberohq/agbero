package xhttp

import (
	"context"
	"io"
	"net/http"
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

	success := false
	if len(h.ExpectedStatus) > 0 {
		for _, s := range h.ExpectedStatus {
			if resp.StatusCode == s {
				success = true
				break
			}
		}
	} else {
		success = resp.StatusCode >= 200 && resp.StatusCode < 300
	}

	if success && h.ExpectedBody != "" {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
		if !strings.Contains(string(bodyBytes), h.ExpectedBody) {
			success = false
		}
	} else {
		// Must drain body to reuse connection if we didn't read it
		io.Copy(io.Discard, resp.Body)
	}

	return success, latency, nil
}
