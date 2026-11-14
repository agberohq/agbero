package bugs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// postJSON is a minimal JSON POST helper for the admin plane.
func postJSON(t *testing.T, url string, payload any, bearer string) (int, string) {
	t.Helper()

	buf, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// getBearer performs an authenticated GET and returns status + body.
func getBearer(t *testing.T, url, bearer string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// adminChallengeToken logs in with the seeded password and returns the
// "challenge" token that /login/challenge accepts as its bearer. The HTTP status
// and body are returned too so callers can observe throttling instead of dying.
func adminChallengeToken(t *testing.T, ts *testServer) (token string, status int, body string) {
	t.Helper()

	status, body = postJSON(t, ts.adminURL("/login"), map[string]string{
		"username": "admin",
		"password": testAdminPassword,
	}, "")
	if status != http.StatusAccepted {
		return "", status, body
	}
	var out struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("setup: decode /login response: %v (%s)", err, body)
	}
	if out.Token == "" {
		t.Fatalf("setup: /login returned no challenge token: %s", body)
	}
	return out.Token, status, body
}
