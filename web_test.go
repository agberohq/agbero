package agbero

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

func TestHandleWeb_ServesIndexAndFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("INDEX"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.html"), []byte("HELLO"), 0644); err != nil {
		t.Fatal(err)
	}

	s := &Server{logger: ll.New("test")}
	web := &woos.Web{Root: woos.WebRoot(root)}

	// index
	{
		req := httptest.NewRequest("GET", "http://static/", nil)
		req.Host = "static.com"
		rr := httptest.NewRecorder()
		s.handleWeb(rr, req, web)

		if rr.Code != 200 {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if rr.Body.String() != "INDEX" {
			t.Fatalf("expected INDEX, got %q", rr.Body.String())
		}
	}

	// file
	{
		req := httptest.NewRequest("GET", "http://static/hello.html", nil)
		req.Host = "static.com"
		rr := httptest.NewRecorder()
		s.handleWeb(rr, req, web)

		if rr.Code != 200 {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if rr.Body.String() != "HELLO" {
			t.Fatalf("expected HELLO, got %q", rr.Body.String())
		}
	}
}

func TestHandleWeb_MethodNotAllowed(t *testing.T) {
	root := t.TempDir()
	s := &Server{logger: ll.New("test")}
	web := &woos.Web{Root: woos.WebRoot(root)}

	req := httptest.NewRequest("POST", "http://static/", nil)
	rr := httptest.NewRecorder()
	s.handleWeb(rr, req, web)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
