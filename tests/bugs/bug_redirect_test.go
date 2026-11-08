package bugs

import (
	"net/http"
	"strings"
	"testing"
)

// Finding: open redirect / host-header injection on the HTTP -> HTTPS redirect —
// internal/handlers/dispatch.go:255-287 derives the redirect target from the raw
// Host header without resolving it through HostManager, so
// `curl -H 'Host: evil.example' http://proxy/` answers
// `301 Location: https://evil.example/`. The 301 is cacheable, so this is also a
// cache-poisoning primitive.
func TestBUG_HTTPSRedirectTrustsHostHeader(t *testing.T) {
	ts := startTestServer(t, serverOpts{https: true, redirect: true})

	resp, body := doRequest(t, http.MethodGet, ts.httpURL(""), "evil.example", "/", nil)

	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "evil.example") {
		t.Fatalf("BUG CONFIRMED: redirectToHTTPS echoed the attacker-controlled Host header "+
			"into Location=%q (status %d). Unknown hosts must not be used to build the "+
			"redirect target (dispatch.go:255-287); resolve through HostManager first. "+
			"Because this is a 301 it is also cache-poisonable.", loc, resp.StatusCode)
	}

	// Either a 404/421 deny (preferred) or a redirect to a configured domain.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMisdirectedRequest {
		if strings.Contains(body, "evil.example") {
			t.Fatalf("BUG CONFIRMED: the unknown-host rejection body echoed the Host header (%q)", body)
		}
		return
	}
	t.Fatalf("unexpected response for an unknown Host: status=%d location=%q", resp.StatusCode, loc)
}
