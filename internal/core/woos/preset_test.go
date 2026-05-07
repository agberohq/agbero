package woos

import (
	"net/http"
	"testing"
)

// Helper

func reqWithHeaders(headers map[string]string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// Baseline — known-dangerous headers with canonical dash form are stripped

func TestSanitizeFastCGIHeaders_Proxy_Stripped(t *testing.T) {
	r := reqWithHeaders(map[string]string{"Proxy": "http://evil.com"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Proxy"]; ok {
		t.Error("Proxy header must be stripped (HTTPoxy CVE-2016-5385)")
	}
}

func TestSanitizeFastCGIHeaders_XForwardedHost_Stripped(t *testing.T) {
	r := reqWithHeaders(map[string]string{"X-Forwarded-Host": "evil.com"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["X-Forwarded-Host"]; ok {
		t.Error("X-Forwarded-Host must be stripped")
	}
}

func TestSanitizeFastCGIHeaders_RemoteAddr_Stripped(t *testing.T) {
	// This header uses underscores in the blocklist entry.
	// The blocklist now stores "remote-addr"; normalisation must match.
	r := reqWithHeaders(map[string]string{"Remote-Addr": "1.2.3.4"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Remote-Addr"]; ok {
		t.Error("Remote-Addr must be stripped")
	}
}

// CVE: Underscore bypass — the actual vulnerability being fixed

// TestSanitizeFastCGIHeaders_UnderscoredProxy is the HTTPoxy bypass test.
// An attacker sends "Proxy" with underscores instead of its canonical form.
// gofast converts both "Proxy" and "Proxy" to HTTP_PROXY identically.
// Before the fix, "proxy" (with underscores) was not in the blocklist.
func TestSanitizeFastCGIHeaders_UnderscoredProxy_Stripped(t *testing.T) {
	// "Proxy" is a single-word header — underscore form isn't meaningful here,
	// but test case-insensitivity thoroughly.
	r := reqWithHeaders(map[string]string{"PROXY": "http://evil.com"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["PROXY"]; ok {
		t.Error("PROXY (uppercase) must be stripped — case insensitive")
	}
}

// TestSanitizeFastCGIHeaders_XForwardedHost_UnderscoreBypass is the primary
// regression test for the reported vulnerability.
//
// Attack: attacker sends X_Forwarded_Host instead of X-Forwarded-Host.
// gofast.MapHeader converts BOTH to HTTP_X_FORWARDED_HOST identically.
// Before fix: "x_forwarded_host" ≠ "x-forwarded-host" → bypass.
// After fix:  normalise "_" → "-" → "x-forwarded-host" → blocked.
func TestSanitizeFastCGIHeaders_XForwardedHost_UnderscoreBypass(t *testing.T) {
	r := reqWithHeaders(map[string]string{"X_Forwarded_Host": "evil.com"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["X_Forwarded_Host"]; ok {
		t.Error("SECURITY: X_Forwarded_Host (underscores) bypassed the blocklist — underscore normalisation not applied")
	}
}

func TestSanitizeFastCGIHeaders_XForwardedFor_UnderscoreBypass(t *testing.T) {
	r := reqWithHeaders(map[string]string{"X_Forwarded_For": "1.2.3.4"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["X_Forwarded_For"]; ok {
		t.Error("SECURITY: X_Forwarded_For (underscores) bypassed the blocklist")
	}
}

func TestSanitizeFastCGIHeaders_XRealIP_UnderscoreBypass(t *testing.T) {
	r := reqWithHeaders(map[string]string{"X_Real_IP": "1.2.3.4"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["X_Real_IP"]; ok {
		t.Error("SECURITY: X_Real_IP (underscores) bypassed the blocklist")
	}
}

func TestSanitizeFastCGIHeaders_ScriptFilename_UnderscoreBypass(t *testing.T) {
	// Old blocklist entry was "script_filename" — only matched underscore form.
	// New entry is "script-filename" — normalisation catches both.
	r := reqWithHeaders(map[string]string{"Script_Filename": "/etc/passwd"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Script_Filename"]; ok {
		t.Error("SECURITY: Script_Filename (underscores) bypassed the blocklist")
	}
}

func TestSanitizeFastCGIHeaders_ScriptFilename_DashForm_Stripped(t *testing.T) {
	r := reqWithHeaders(map[string]string{"Script-Filename": "/etc/passwd"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Script-Filename"]; ok {
		t.Error("Script-Filename (dashes) must also be stripped")
	}
}

func TestSanitizeFastCGIHeaders_RemoteAddr_UnderscoreBypass(t *testing.T) {
	// Old entry was "remote_addr" — blocked underscore but not dash.
	// Both must now be blocked.
	r := reqWithHeaders(map[string]string{"Remote_Addr": "5.5.5.5"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Remote_Addr"]; ok {
		t.Error("SECURITY: Remote_Addr (underscores) bypassed the blocklist")
	}
}

// TestSanitizeFastCGIHeaders_MixedSeparators tests every combination of
// separator that gofast collapses to the same CGI variable name.
func TestSanitizeFastCGIHeaders_MixedSeparators(t *testing.T) {
	variants := []string{
		"X-Forwarded-Host", // canonical dash form
		"X_Forwarded_Host", // underscore form (the bypass)
		"x_forwarded_host", // lowercase underscore
		"X-Forwarded_Host", // mixed (dash then underscore)
		"X_Forwarded-Host", // mixed (underscore then dash)
	}
	for _, variant := range variants {
		r := reqWithHeaders(map[string]string{variant: "evil.com"})
		safe := SanitizeFastCGIHeaders(r)
		if _, ok := safe[variant]; ok {
			t.Errorf("SECURITY: header variant %q was not stripped — all separator variants must be blocked", variant)
		}
	}
}

// HTTP_ prefix injection — blocked regardless of separator style

func TestSanitizeFastCGIHeaders_HttpPrefixDash_Stripped(t *testing.T) {
	// "Http-Foo" → normalised "http-foo" → HasPrefix("http-") → stripped
	r := reqWithHeaders(map[string]string{"Http-Foo": "bar"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Http-Foo"]; ok {
		t.Error("Http-Foo must be stripped (http- prefix)")
	}
}

func TestSanitizeFastCGIHeaders_HttpPrefixUnderscore_Stripped(t *testing.T) {
	// "Http_Foo" → normalised "http-foo" → HasPrefix("http-") → stripped
	r := reqWithHeaders(map[string]string{"Http_Foo": "bar"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Http_Foo"]; ok {
		t.Error("Http_Foo (underscore) must be stripped (normalises to http- prefix)")
	}
}

func TestSanitizeFastCGIHeaders_HttpHostUnderscore_Stripped(t *testing.T) {
	// "Http_Host" would become HTTP_HTTP_HOST — double injection attempt.
	r := reqWithHeaders(map[string]string{"Http_Host": "evil.com"})
	safe := SanitizeFastCGIHeaders(r)
	if _, ok := safe["Http_Host"]; ok {
		t.Error("Http_Host must be stripped")
	}
}

// Safe headers — must pass through unmodified

func TestSanitizeFastCGIHeaders_SafeHeaders_Preserved(t *testing.T) {
	safeHeaders := map[string]string{
		"Accept":          "text/html",
		"Accept-Language": "en-US",
		"User-Agent":      "Mozilla/5.0",
		"Authorization":   "Bearer token123",
		"Cache-Control":   "no-cache",
		"X-Custom-Header": "custom-value",
		"X-Request-Id":    "abc-123",
	}
	r := reqWithHeaders(safeHeaders)
	safe := SanitizeFastCGIHeaders(r)

	for k, want := range safeHeaders {
		got := safe.Get(k)
		if got != want {
			t.Errorf("safe header %q: got %q, want %q", k, got, want)
		}
	}
}

func TestSanitizeFastCGIHeaders_DoesNotModifyOriginal(t *testing.T) {
	r := reqWithHeaders(map[string]string{
		"Proxy":           "http://evil.com",
		"X-Custom-Header": "safe-value",
	})
	origLen := len(r.Header)
	SanitizeFastCGIHeaders(r)
	if len(r.Header) != origLen {
		t.Error("SanitizeFastCGIHeaders must not modify r.Header in place")
	}
	if r.Header.Get("Proxy") != "http://evil.com" {
		t.Error("original request Proxy header was removed — must return a copy")
	}
}

// DangerousFastCGIHeaders — all entries use dashes (not underscores)

func TestDangerousFastCGIHeaders_AllEntriesUseDashes(t *testing.T) {
	for key := range DangerousFastCGIHeaders {
		if len(key) > 0 && containsUnderscore(key) {
			t.Errorf("DangerousFastCGIHeaders entry %q contains underscore — must use dashes only (normalisation is done at lookup time)", key)
		}
	}
}

func containsUnderscore(s string) bool {
	for _, c := range s {
		if c == '_' {
			return true
		}
	}
	return false
}
