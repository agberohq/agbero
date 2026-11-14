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

// TestBUG_HedgedResponseAbortDoesNotKillProcess reproduces the panic where
// httputil.ReverseProxy raises http.ErrAbortHandler in a jack hedge goroutine.
// net/http only recovers that panic on the serving goroutine.
func TestBUG_HedgedResponseAbortDoesNotKillProcess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer upstream.Close()

	res := resource.New()
	t.Cleanup(func() { res.Close() })
	res.Hedger = jack.NewHedger(jack.HedgeWithDelay(time.Millisecond))

	b, err := xhttp.NewBackend(xhttp.ConfigBackend{
		Server:    alaye.Server{Address: expect.Address(upstream.URL)},
		Route:     &alaye.Route{Path: "/"},
		Domains:   []string{"abort.localhost"},
		Resource:  res,
		UseHedger: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	// Run through a real HTTP server so net/http owns the serving goroutine and
	// can recover the intentional http.ErrAbortHandler.
	front := httptest.NewServer(b)
	defer front.Close()
	resp, err := http.Get(front.URL)
	if err == nil {
		resp.Body.Close()
	}
	time.Sleep(50 * time.Millisecond)
}
