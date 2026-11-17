package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func startRelay(t *testing.T, addr string) *Server {
	t.Helper()
	srv := NewServer(ServerConfig{
		Name: "agents", BaseDomain: "relay.test", Listen: addr,
		TLSConfig: testTLS(t), EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{AllowHTTP: true},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	return srv
}

func startAgent(t *testing.T, relayAddr, local, agent string, pool int) (context.CancelFunc, *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	client := NewClient(ClientConfig{
		Agent: agent, Relay: "https://" + relayAddr, Enroll: "enroll-secret",
		Local: local, LocalInsecure: true, Insecure: true, Pool: pool,
		Exposes: []alaye.Expose{{ID: "show", Path: true, LocalHost: "show.localhost"}},
	})
	go client.Run(ctx)
	return cancel, client
}

func getThrough(t *testing.T, srv *Server, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://relay.test"+path, nil)
	req.Host = "relay.test"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

func waitServed(t *testing.T, srv *Server, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body := getThrough(t, srv, path)
		if code == http.StatusOK && (want == "" || body == want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: last response %d %q", path, code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// burst asserts a run of sequential requests all succeed; a route left bound to
// a dead session shows up here as a 502 after recovery.
func burst(t *testing.T, srv *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if code, body := getThrough(t, srv, "/show"); code != http.StatusOK {
			t.Fatalf("burst request %d: %d %q", i, code, body)
		}
	}
}

// TestAgentSurvivesRelayRestart models a relay deploy or config reload: the
// listener and all sessions are torn down, then a new relay starts on the same
// address. The agent must re-authenticate and the exposure must come back.
func TestAgentSurvivesRelayRestart(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	cancel, _ := startAgent(t, addr, local.URL, "alice", 2)
	defer cancel()
	waitServed(t, srv, "/show", "ok")

	_ = srv.Close()

	next := startRelay(t, addr)
	defer next.Close()
	waitServed(t, next, "/show", "ok")
	burst(t, next, 10)

	if snap := next.Snapshot(); len(snap.Routes) != 1 || !snap.Routes[0].Live {
		t.Fatalf("routes after restart = %+v, want one live route", snap.Routes)
	}
}

// TestAgentSurvivesRepeatedRelayRestarts is the reload-loop case: sessions are
// torn down every few hundred milliseconds. Requests must keep succeeding once
// the relay is back, without accumulating dead routes.
func TestAgentSurvivesRepeatedRelayRestarts(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	cancel, _ := startAgent(t, addr, local.URL, "alice", 2)
	defer cancel()
	waitServed(t, srv, "/show", "ok")

	for i := 0; i < 3; i++ {
		_ = srv.Close()
		time.Sleep(150 * time.Millisecond)
		srv = startRelay(t, addr)
		waitServed(t, srv, "/show", "ok")
		burst(t, srv, 5)
	}
	srv.Close()

	// A final restart must still produce exactly one live route, not one per
	// reconnect.
	final := startRelay(t, addr)
	defer final.Close()
	waitServed(t, final, "/show", "ok")
	burst(t, final, 10)
	snap := final.Snapshot()
	if len(snap.Routes) != 1 {
		t.Fatalf("routes = %+v, want exactly one", snap.Routes)
	}
}

// TestAgentHandlesConcurrentRequests drives more parallel requests than pooled
// tunnel connections, which is where a single-use pool starves.
func TestAgentHandlesConcurrentRequests(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "ok")
	}))
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	defer srv.Close()
	cancel, _ := startAgent(t, addr, local.URL, "alice", 4)
	defer cancel()
	waitServed(t, srv, "/show", "ok")

	const n = 12
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
			req.Host = "relay.test"
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "ok" {
				errs <- fmt.Sprintf("request %d: %d %q", i, rr.Code, rr.Body.String())
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestRelayStreamsRequestBody sends a body far larger than the agent's first
// read, so the tunnel must stream the remainder rather than truncate it.
func TestRelayStreamsRequestBody(t *testing.T) {
	body := bytes.Repeat([]byte("agbero-relay-body-"), 16*1024) // ~300KB
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotSum := sha256.Sum256(got)
		fmt.Fprintf(w, "%d %s", len(got), hex.EncodeToString(gotSum[:]))
	}))
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	defer srv.Close()
	cancel, _ := startAgent(t, addr, local.URL, "alice", 2)
	defer cancel()
	waitServed(t, srv, "/show", "")

	req := httptest.NewRequest(http.MethodPost, "http://relay.test/show", bytes.NewReader(body))
	req.Host = "relay.test"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body %q", rr.Code, rr.Body.String())
	}
	wantBody := fmt.Sprintf("%d %s", len(body), want)
	if got := strings.TrimSpace(rr.Body.String()); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}

// TestRelayStreamsResponseChunks verifies that a multipart streaming response
// is delivered completely and in order.
func TestRelayStreamsResponseChunks(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Error("local writer cannot flush")
			return
		}
		for i := 0; i < 8; i++ {
			fmt.Fprintf(w, "chunk-%d;", i)
			fl.Flush()
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	defer srv.Close()
	cancel, _ := startAgent(t, addr, local.URL, "alice", 2)
	defer cancel()
	waitServed(t, srv, "/show", "")

	req := httptest.NewRequest(http.MethodGet, "http://relay.test/show", nil)
	req.Host = "relay.test"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var want strings.Builder
	for i := 0; i < 8; i++ {
		fmt.Fprintf(&want, "chunk-%d;", i)
	}
	if got := rr.Body.String(); got != want.String() {
		t.Fatalf("body = %q, want %q", got, want.String())
	}
}

// TestHeartbeatPingDoesNotDropRoutes drives a ping through a control session and
// asserts the registered routes survive; treating a ping as a registration
// would silently remove every exposure.
func TestHeartbeatPingDoesNotDropRoutes(t *testing.T) {
	srv := NewServer(ServerConfig{
		Name: "agents", BaseDomain: "relay.test",
		Policy: alaye.RelayPolicy{AllowHTTP: true},
	})
	srv.agents = newAgentStore(nil)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	reg := registration{Exposes: []registeredExpose{{ID: "show", Path: true}}}
	done := make(chan struct{})
	go func() {
		srv.handleControl(context.Background(), serverConn, nil, "test", "alice", reg)
		close(done)
	}()

	// Consume the registration ack.
	var ackFrame ack
	if err := readFrame(clientConn, &ackFrame); err != nil {
		t.Fatal(err)
	}
	if !ackFrame.OK {
		t.Fatalf("registration rejected: %s", ackFrame.Error)
	}

	if err := writeFrame(clientConn, registration{Kind: framePing}); err != nil {
		t.Fatal(err)
	}
	var pingAck ack
	if err := readFrame(clientConn, &pingAck); err != nil {
		t.Fatal(err)
	}
	if !pingAck.OK {
		t.Fatalf("ping rejected: %s", pingAck.Error)
	}

	srv.mu.RLock()
	rt := srv.routes["/show"]
	srv.mu.RUnlock()
	if rt == nil {
		t.Fatal("ping removed the registered route")
	}

	_ = clientConn.Close()
	<-done
}

// TestAgentSessionStaysIdleWithAgberoTarget models the production idle case:
// the local agbero closes idle local connections after its read-header timeout,
// and a large pool of tunnel connections sits idle. No session may be replaced
// and every request after the idle period must still be served.
func TestAgentSessionStaysIdleWithAgberoTarget(t *testing.T) {
	local := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	local.Config.ReadHeaderTimeout = time.Second
	local.StartTLS()
	defer local.Close()

	addr := freeAddr(t)
	srv := startRelay(t, addr)
	defer srv.Close()
	cancel, _ := startAgent(t, addr, local.URL, "alice", 8)
	defer cancel()
	waitServed(t, srv, "/show", "ok")

	// Idle for several multiples of the local read-header timeout.
	time.Sleep(12 * time.Second)
	waitServed(t, srv, "/show", "ok")

	snap := srv.Snapshot()
	if len(snap.Agents) != 1 {
		t.Fatalf("agents = %d, want 1", len(snap.Agents))
	}
	if snap.Agents[0].Reconnects != 0 {
		t.Fatalf("reconnects = %d after idle, want 0 (the session was replaced)", snap.Agents[0].Reconnects)
	}
	if snap.Agents[0].LastError != "" {
		t.Fatalf("last error after idle: %s", snap.Agents[0].LastError)
	}
}

// TestLegacyAgentGetsUpgradeError documents the wire break: an agent that
// speaks the old data-connection protocol is told to rebuild instead of
// silently hanging or being half-served.
func TestLegacyAgentGetsUpgradeError(t *testing.T) {
	addr := freeAddr(t)
	srv := startRelay(t, addr)
	defer srv.Close()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, hello{Kind: frameControl, Agent: "alice", EnrollToken: "enroll-secret"}); err != nil {
		t.Fatal(err)
	}
	var a ack
	if err := readFrame(conn, &a); err != nil {
		t.Fatal(err)
	}
	if a.OK {
		t.Fatal("legacy control connection was accepted")
	}
	if !strings.Contains(a.Error, "mux") {
		t.Fatalf("error = %q, want the mux upgrade message", a.Error)
	}
}
