package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/handlers/xtcp"
	"github.com/agberohq/agbero/internal/handlers/xudp"
	"github.com/quic-go/quic-go/http3"
)

type Listener interface {
	Start() error
	Stop(ctx context.Context) error
	Addr() string
	Kind() string
}

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

type TCPListener struct {
	Proxy *xtcp.Proxy
}

func (t *TCPListener) Start() error {
	return t.Proxy.Start()
}

func (t *TCPListener) Stop(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		// No deadline in context — use a reasonable default so we don't
		// wait forever, but still give connections time to drain.
		deadline = time.Now().Add(30 * time.Second)
	}
	done := make(chan struct{})
	go func() {
		t.Proxy.GracefulStop(deadline)
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

// UDPListener wraps an xudp.Proxy and implements the Listener interface.
type UDPListener struct {
	Proxy *xudp.Proxy
}

func (u *UDPListener) Start() error {
	return u.Proxy.Start()
}

func (u *UDPListener) Stop(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		u.Proxy.Stop()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (u *UDPListener) Addr() string { return u.Proxy.Listen }
func (u *UDPListener) Kind() string { return "udp" }
