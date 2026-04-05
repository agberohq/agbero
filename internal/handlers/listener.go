package handlers

import (
	"context"
	"net/http"

	"github.com/agberohq/agbero/internal/handlers/xtcp"
	"github.com/quic-go/quic-go/http3"
)

type Listener interface {
	Start() error
	Stop(ctx context.Context) error
	Addr() string
	Kind() string
}

// HTTP Listener

type HTTPListener struct {
	Srv     *http.Server
	Tracker *ConnTracker
	IsTLS   bool
}

func (h *HTTPListener) Start() error {
	if h.IsTLS {
		return h.Srv.ListenAndServeTLS("", "")
	}
	return h.Srv.ListenAndServe()
}

func (h *HTTPListener) Stop(ctx context.Context) error {
	err := h.Srv.Shutdown(ctx)
	h.Tracker.Wait(ctx)
	return err
}

func (h *HTTPListener) Addr() string { return h.Srv.Addr }
func (h *HTTPListener) Kind() string {
	if h.IsTLS {
		return "https"
	}
	return "http"
}

// HTTP/3 (QUIC) Listener

type H3Listener struct {
	Srv *http3.Server
}

func (h *H3Listener) Start() error {
	return h.Srv.ListenAndServe()
}

func (h *H3Listener) Stop(ctx context.Context) error {
	err := h.Srv.Shutdown(ctx)
	if err != nil {
		h.Srv.Close()
	}
	return err
}

func (h *H3Listener) Addr() string { return h.Srv.Addr }
func (h *H3Listener) Kind() string { return "h3" }

// TCP Proxy Listener

type TCPListener struct {
	Proxy *xtcp.Proxy
}

func (t *TCPListener) Start() error {
	return t.Proxy.Start()
}

func (t *TCPListener) Stop(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		t.Proxy.Stop()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *TCPListener) Addr() string { return t.Proxy.Listen }
func (t *TCPListener) Kind() string { return "tcp" }
