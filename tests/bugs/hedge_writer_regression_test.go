package bugs

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/handlers/xhttp"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/jack"
)

// TestBUG_HedgeLoserCannotWriteAfterWriterRelease is an end-to-end smoke test
// for the nil basicStatusWriter panic. The unit-level lifecycle assertion lives
// in internal/handlers/xhttp/writers_test.go because hedgeWriter is unexported.
func TestBUG_HedgeLoserCannotWriteAfterWriterRelease(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	res := resource.New()
	t.Cleanup(func() { res.Close() })
	res.Hedger = jack.NewHedger(jack.HedgeWithDelay(time.Millisecond))

	b, err := xhttp.NewBackend(xhttp.ConfigBackend{
		Server:    alaye.Server{Address: expect.Address(upstream.URL)},
		Route:     &alaye.Route{Path: "/"},
		Domains:   []string{"hedge.localhost"},
		Resource:  res,
		UseHedger: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// Let the losing hedge attempt finish after the handler has returned.
	time.Sleep(40 * time.Millisecond)
}
