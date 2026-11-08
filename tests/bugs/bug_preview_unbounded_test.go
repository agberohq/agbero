package bugs

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BUG-L3 — POST /api/v1/discovery/preview body/response limits.
//
// create()  (operation/api/host.go:389) and update() (:503) both wrap the body
// in http.MaxBytesReader(w, r.Body, def.HostConfigMaxBytes) (4 MiB), so an
// oversized payload is rejected with 413 before it is decoded. preview()
// (:681) used to decode straight into hostCreateRequest with no limit, so the
// daemon allocated the full body before any validation ran — and then
// amplified it through woos.DefaultHost + the HCL renderer into a rendered
// response of the same size. That was a one-request memory/CPU DoS of the
// admin plane (which shares the proxy process).
//
// Fixed in internal/operation/api/host.go: preview now wraps the body in
// MaxBytesReader (413 like create/update) and rejects a rendered response
// larger than def.HostConfigMaxBytes.
//
// This test now asserts the fixed behaviour and FAILS if it disappears.

const previewBodyMax = 6 * 1024 * 1024 // > def.HostConfigMaxBytes (4 MiB)

func previewOversizedPayload() string {
	pad := strings.Repeat("A", previewBodyMax)
	return fmt.Sprintf(`{"domain":"big.example","config":{"domains":["big.example"],`+
		`"routes":[{"path":"/","web":{"root":"%s"}}]}}`, pad)
}

func TestBUG_DiscoveryPreviewRejectsOversizedBody(t *testing.T) {
	router, _, _ := newHostAPI(t)
	payload := previewOversizedPayload()

	t.Run("create is capped (reference behaviour)", func(t *testing.T) {
		createRR := httptest.NewRecorder()
		createReq := httptest.NewRequest(http.MethodPost, "/discovery/", strings.NewReader(payload))
		createReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(createRR, createReq)
		if createRR.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("create should reject a %d-byte body with 413 (MaxBytesReader), got %d: %s",
				previewBodyMax, createRR.Code, createRR.Body.String())
		}
	})

	t.Run("preview must be capped too", func(t *testing.T) {
		previewRR := httptest.NewRecorder()
		previewReq := httptest.NewRequest(http.MethodPost, "/discovery/preview", strings.NewReader(payload))
		previewReq.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(previewRR, previewReq)

		if previewRR.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("preview must reject a %d-byte body with 413 (MaxBytesReader), got %d: %s",
				previewBodyMax, previewRR.Code, previewRR.Body.String())
		}
	})
}
