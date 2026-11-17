package relay

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/hashicorp/yamux"
)

func newTestSession(agent string) *session {
	return &session{
		agent:  agent,
		done:   make(chan struct{}),
		reg:    registration{},
		remote: "test",
	}
}

// TestReconnectTakesOverRoute covers the reconnect race: the new control
// connection registers while the previous session still owns the route. The
// route must follow the live session instead of staying bound to the dead one
// (which answered 502) or being removed by its cleanup (which answered 404).
func TestReconnectTakesOverRoute(t *testing.T) {
	srv := NewServer(ServerConfig{Name: "agents", BaseDomain: "relay.test", Policy: alaye.RelayPolicy{AllowHTTP: true}})
	reg := registration{Exposes: []registeredExpose{{ID: "show", Path: true}}}

	old := newTestSession("alice")
	if err := srv.applyRegistration(old, reg); err != nil {
		t.Fatal(err)
	}

	next := newTestSession("alice")
	if err := srv.applyRegistration(next, reg); err != nil {
		t.Fatal(err)
	}

	srv.mu.RLock()
	rt := srv.routes["/show"]
	srv.mu.RUnlock()
	if rt == nil {
		t.Fatal("route disappeared during reconnect")
	}
	if rt.session != next {
		t.Fatal("route is still bound to the previous session")
	}

	// The previous session's cleanup runs afterwards and must not disturb the
	// route now owned by the live session.
	srv.mu.Lock()
	for key, r := range srv.routes {
		if r.session == old {
			delete(srv.routes, key)
		}
	}
	srv.mu.Unlock()
	if srv.routes["/show"] == nil {
		t.Fatal("cleanup of the previous session removed the live route")
	}
}

// TestAgentTakesOverExposureAfterReconnect kills the relay-side session and
// verifies that the agent reconnects quickly and the exposure keeps serving.
func TestAgentTakesOverExposureAfterReconnect(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()

	srv := NewServer(ServerConfig{
		Name: "agents", BaseDomain: "relay.test", Listen: "127.0.0.1:0",
		TLSConfig: testTLS(t), EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{AllowHTTP: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent: "alice", Relay: "https://" + srv.Addr(), Enroll: "enroll-secret",
		Local: local.URL, Insecure: true, Pool: 2,
		Exposes: []alaye.Expose{{ID: "show", Path: true, LocalHost: "show.localhost"}},
	})
	go client.Run(ctx)

	get := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
		req.Host = "relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code, strings.TrimSpace(rr.Body.String())
	}
	waitOK := func(what string) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			if code, body := get(); code == http.StatusOK {
				return
			} else if time.Now().After(deadline) {
				t.Fatalf("%s: last response %d %q", what, code, body)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitOK("initial exposure")

	for i := 0; i < 3; i++ {
		srv.mu.RLock()
		sess := srv.sessions["alice"]
		srv.mu.RUnlock()
		if sess == nil {
			t.Fatal("agent session missing")
		}
		sess.close()

		deadline := time.Now().Add(8 * time.Second)
		for {
			srv.mu.RLock()
			now := srv.sessions["alice"]
			srv.mu.RUnlock()
			if now != nil && now != sess {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("reconnect %d did not happen", i)
			}
			time.Sleep(20 * time.Millisecond)
		}
		waitOK("exposure after reconnect")
	}

	snap := srv.Snapshot()
	if len(snap.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(snap.Agents))
	}
	if snap.Agents[0].Reconnects < 3 {
		t.Fatalf("reconnects = %d, want at least 3", snap.Agents[0].Reconnects)
	}
	if len(snap.Routes) != 1 || !snap.Routes[0].Live || snap.Routes[0].Agent != "alice" {
		t.Fatalf("routes = %+v, want one live route owned by alice", snap.Routes)
	}
}

func TestSnapshotMarksDeadRoutes(t *testing.T) {
	srv := NewServer(ServerConfig{Name: "agents", BaseDomain: "relay.test", Policy: alaye.RelayPolicy{AllowHTTP: true}})
	sess := newTestSession("alice")
	srv.mu.Lock()
	srv.sessions["alice"] = sess
	srv.mu.Unlock()
	if err := srv.applyRegistration(sess, registration{Exposes: []registeredExpose{{ID: "show", Path: true}}}); err != nil {
		t.Fatal(err)
	}
	if snap := srv.Snapshot(); len(snap.Routes) != 1 || !snap.Routes[0].Live {
		t.Fatalf("routes = %+v, want one live route", snap.Routes)
	}
	sess.close()
	if snap := srv.Snapshot(); len(snap.Routes) != 1 || snap.Routes[0].Live {
		t.Fatalf("routes = %+v, a closed session must not be reported live", snap.Routes)
	}
}

// TestClientHeartbeatsControlConn verifies that a relay advertising a heartbeat
// interval receives pings, that the pings are answered, and that the client does
// not tear the session down when those answers arrive.
func TestClientHeartbeatsControlConn(t *testing.T) {
	cfg := testTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		pings   int
		second  bool
		reached chan struct{}
	}
	res := &result{reached: make(chan struct{})}
	go func() {
		defer close(res.reached)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		magic := make([]byte, len(muxMagic))
		if _, err := io.ReadFull(conn, magic); err != nil || string(magic) != muxMagic {
			return
		}
		mux, err := yamux.Server(conn, newMuxConfig())
		if err != nil {
			return
		}
		defer mux.Close()
		conn, err = mux.AcceptStream()
		if err != nil {
			return
		}
		var h hello
		if readFrame(conn, &h) != nil {
			return
		}
		if writeFrame(conn, ack{OK: true}) != nil {
			return
		}
		var reg registration
		if readFrame(conn, &reg) != nil {
			return
		}
		if len(reg.Exposes) != 1 {
			return
		}
		if writeFrame(conn, ack{OK: true, HeartbeatSeconds: 1}) != nil {
			return
		}
		for {
			var f registration
			if err := readFrame(conn, &f); err != nil {
				return
			}
			if f.Kind != framePing {
				res.second = true // a second control hello or re-registration
				return
			}
			res.pings++
			if writeFrame(conn, ack{OK: true}) != nil {
				return
			}
			if res.pings >= 2 {
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent: "alice", Relay: "https://" + ln.Addr().String(), Enroll: "tok",
		Local: "http://127.0.0.1:1", Insecure: true, Pool: 1,
		Exposes: []alaye.Expose{{ID: "show", Path: true}},
	})
	go client.Run(ctx)

	select {
	case <-res.reached:
	case <-time.After(6 * time.Second):
		t.Fatal("timed out waiting for heartbeats")
	}
	if res.second {
		t.Fatal("client re-registered instead of keeping the control connection")
	}
	if res.pings < 2 {
		t.Fatalf("heartbeats received = %d, want at least 2", res.pings)
	}
}
