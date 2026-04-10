package stash

import (
	"context"
	"net/http"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req.Host = "example.com"
	baseKey := Key(req, nil)

	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2.Host = "example.com"
	if Key(req2, nil) != baseKey {
		t.Error("same request should have same key")
	}

	req3, _ := http.NewRequest("POST", "https://example.com/test", nil)
	req3.Host = "example.com"
	if Key(req3, nil) == baseKey {
		t.Error("different method should have different key")
	}

	req4, _ := http.NewRequest("GET", "https://example.com/other", nil)
	req4.Host = "example.com"
	if Key(req4, nil) == baseKey {
		t.Error("different path should have different key")
	}

	req5, _ := http.NewRequest("GET", "https://example.com/test?q=foo", nil)
	req5.Host = "example.com"
	if Key(req5, nil) == baseKey {
		t.Error("query string should change key")
	}

	req6, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req6.Host = "example.com"
	req6.Header.Set("Accept", "application/json")
	if Key(req6, nil) == baseKey {
		t.Error("Accept header should affect cache key")
	}

	req7, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req7.Host = "example.com"
	req7.Header.Set("Accept-Language", "en")
	if Key(req7, nil) == baseKey {
		t.Error("Accept-Language header should affect cache key")
	}

	req8, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req8.Host = "example.com"
	req8.Header.Set("Accept-Encoding", "gzip")
	if Key(req8, nil) == baseKey {
		t.Error("Accept-Encoding header should affect cache key")
	}
}

func TestKeyGenerationWithScope(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/test?q=foo&r=bar", nil)
	req.Host = "example.com"
	req.Header.Set("X-Custom", "value")
	req.Header.Set("Accept-Language", "en-US")

	scope := []string{"header:X-Custom", "query"}
	key1 := Key(req, scope)

	req2, _ := http.NewRequest("GET", "https://example.com/test?q=foo&r=bar", nil)
	req2.Host = "example.com"
	req2.Header.Set("X-Custom", "different")
	req2.Header.Set("Accept-Language", "en-US")
	key2 := Key(req2, scope)

	if key1 == key2 {
		t.Error("different header value should change key when header in scope")
	}

	req3, _ := http.NewRequest("GET", "https://example.com/test?q=bar&r=bar", nil)
	req3.Host = "example.com"
	req3.Header.Set("X-Custom", "value")
	req3.Header.Set("Accept-Language", "en-US")
	key3 := Key(req3, scope)

	if key1 == key3 {
		t.Error("different query param should change key when query in scope")
	}

	req4, _ := http.NewRequest("GET", "https://example.com/test?q=foo&r=bar", nil)
	req4.Host = "example.com"
	req4.Header.Set("X-Custom", "value")
	key4 := Key(req4, []string{})

	if key1 == key4 {
		t.Error("scope should affect key generation")
	}
}

func TestKeyGenerationWithAuthScope(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req.Host = "example.com"

	ctx := context.WithValue(req.Context(), "auth_id", "user123")
	req = req.WithContext(ctx)

	scope := []string{"auth"}
	key1 := Key(req, scope)

	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2.Host = "example.com"
	ctx2 := context.WithValue(req2.Context(), "auth_id", "user456")
	req2 = req2.WithContext(ctx2)
	key2 := Key(req2, scope)

	if key1 == key2 {
		t.Error("different auth ID should change key when auth in scope")
	}

	req3, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req3.Host = "example.com"
	key3 := Key(req3, scope)

	if key1 == key3 {
		t.Error("missing auth ID should change key when auth in scope")
	}
}

func TestKeyWithCustomHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req.Host = "example.com"
	req.Header.Set("X-Custom", "value1")
	req.Header.Set("X-Another", "value2")
	req.Header.Set("Accept", "text/html")

	customHeaders := []string{"X-Custom", "X-Another"}

	key1 := KeyWithCustomHeaders(req, nil, customHeaders)

	req2, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req2.Host = "example.com"
	req2.Header.Set("X-Custom", "value1")
	req2.Header.Set("X-Another", "value2")
	req2.Header.Set("Accept", "text/html")
	key2 := KeyWithCustomHeaders(req2, nil, customHeaders)

	if key1 != key2 {
		t.Error("same request should have same key")
	}

	req3, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req3.Host = "example.com"
	req3.Header.Set("X-Custom", "different")
	req3.Header.Set("X-Another", "value2")
	key3 := KeyWithCustomHeaders(req3, nil, customHeaders)

	if key1 == key3 {
		t.Error("different header value should change key")
	}

	req4, _ := http.NewRequest("GET", "https://example.com/test", nil)
	req4.Host = "example.com"
	key4 := KeyWithCustomHeaders(req4, nil, customHeaders)

	if key1 == key4 {
		t.Error("missing headers should change key")
	}
}

func TestKeyWithCustomHeadersAndScope(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/test?q=foo", nil)
	req.Host = "example.com"
	req.Header.Set("X-Custom", "value")
	req.Header.Set("X-Another", "value2")

	customHeaders := []string{"X-Custom"}
	scope := []string{"header:X-Another", "query"}

	key1 := KeyWithCustomHeaders(req, scope, customHeaders)

	req2, _ := http.NewRequest("GET", "https://example.com/test?q=foo", nil)
	req2.Host = "example.com"
	req2.Header.Set("X-Custom", "different")
	req2.Header.Set("X-Another", "value2")
	key2 := KeyWithCustomHeaders(req2, scope, customHeaders)

	if key1 == key2 {
		t.Error("different custom header should change key")
	}

	req3, _ := http.NewRequest("GET", "https://example.com/test?q=bar", nil)
	req3.Host = "example.com"
	req3.Header.Set("X-Custom", "value")
	req3.Header.Set("X-Another", "value2")
	key3 := KeyWithCustomHeaders(req3, scope, customHeaders)

	if key1 == key3 {
		t.Error("different query param should change key")
	}

	req4, _ := http.NewRequest("GET", "https://example.com/test?q=foo", nil)
	req4.Host = "example.com"
	req4.Header.Set("X-Custom", "value")
	req4.Header.Set("X-Another", "different")
	key4 := KeyWithCustomHeaders(req4, scope, customHeaders)

	if key1 == key4 {
		t.Error("different scoped header should change key")
	}
}
