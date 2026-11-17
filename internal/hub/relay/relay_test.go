package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/hashicorp/yamux"
)

func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func TestServerAgentHTTPPath(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "local.test" {
			t.Errorf("Host = %q, want local.test", r.Host)
		}
		_, _ = io.WriteString(w, "relay body "+r.URL.Path)
	}))
	defer local.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowHTTP: true,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Enroll:   "enroll-secret",
		Local:    local.URL,
		Insecure: true,
		Pool:     2,
		Exposes: []alaye.Expose{{
			ID:        "hello",
			Via:       "default",
			Path:      true,
			LocalPath: "/",
			LocalHost: "local.test",
		}},
	})
	go client.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "http://relay.test/hello/world", nil)
		req.Host = "relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			if !strings.Contains(rr.Body.String(), "relay body /world") {
				t.Fatalf("body = %q", rr.Body.String())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not become ready, last status %d body %q", rr.Code, rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerRejectsBadAgentToken(t *testing.T) {
	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowHTTP: true,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	conn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := writeFrame(conn, hello{Kind: frameControl, Agent: "alice", Token: "wrong"}); err != nil {
		t.Fatal(err)
	}
	var a ack
	if err := readFrame(conn, &a); err != nil {
		t.Fatal(err)
	}
	if a.OK {
		t.Fatal("bad token was accepted")
	}
}

func TestServerAgentHTTPSubdomain(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "subdomain "+r.URL.Path)
	}))
	defer local.Close()

	registered := make(chan string, 1)
	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowSubdomain: true,
		},
		RegisterHost: func(domain string) { registered <- domain },
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Enroll:   "enroll-secret",
		Local:    local.URL,
		Insecure: true,
		Pool:     2,
		Exposes: []alaye.Expose{{
			ID:        "hello",
			Via:       "default",
			Subdomain: true,
			LocalPath: "/",
			LocalHost: "local.test",
		}},
	})
	go client.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "http://hello.relay.test/world", nil)
		req.Host = "hello.relay.test"
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			if !strings.Contains(rr.Body.String(), "subdomain /world") {
				t.Fatalf("body = %q", rr.Body.String())
			}
			select {
			case domain := <-registered:
				if domain != "hello.relay.test" {
					t.Fatalf("registered host = %q", domain)
				}
			default:
				t.Fatal("subdomain host was not registered")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("subdomain relay did not become ready, last status %d body %q", rr.Code, rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerAgentTCP(t *testing.T) {
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	go func() {
		for {
			c, err := local.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	public, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := public.Addr().(*net.TCPAddr).Port
	_ = public.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowTCPPorts: []string{fmt.Sprintf("%d", publicPort)},
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Enroll:   "enroll-secret",
		Local:    "http://127.0.0.1:1",
		Insecure: true,
		Pool:     1,
		Exposes: []alaye.Expose{{
			ID:  "redis",
			Via: "default",
			TCP: &alaye.RelayTarget{
				PublicPort: publicPort,
				Local:      local.Addr().String(),
			},
		}},
	})
	go client.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", publicPort))
		if err == nil {
			_, _ = conn.Write([]byte("ping"))
			buf := make([]byte, 4)
			_, _ = io.ReadFull(conn, buf)
			_ = conn.Close()
			if string(buf) == "ping" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tcp relay did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerAgentUDP(t *testing.T) {
	local, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = local.Close() }()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := local.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = local.WriteTo(buf[:n], addr)
		}
	}()

	public, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicPort := public.LocalAddr().(*net.UDPAddr).Port
	_ = public.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowUDPPorts: []string{fmt.Sprintf("%d", publicPort)},
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Enroll:   "enroll-secret",
		Local:    "http://127.0.0.1:1",
		Insecure: true,
		Pool:     1,
		Exposes: []alaye.Expose{{
			ID:  "dns",
			Via: "default",
			UDP: &alaye.RelayTarget{
				PublicPort: publicPort,
				Local:      local.LocalAddr().String(),
			},
		}},
	})
	go client.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", publicPort))
		if err == nil {
			_, _ = conn.Write([]byte("ping"))
			_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 4)
			_, _ = conn.Read(buf)
			_ = conn.Close()
			if string(buf) == "ping" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("udp relay did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerEnrollment(t *testing.T) {
	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowHTTP: true,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	conn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(muxMagic)); err != nil {
		t.Fatal(err)
	}
	mux, err := yamux.Client(conn, newMuxConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mux.Close() }()
	stream, err := mux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if err := writeFrame(stream, hello{Kind: frameControl, Agent: "alice", EnrollToken: "enroll-secret"}); err != nil {
		t.Fatal(err)
	}
	var a ack
	if err := readFrame(stream, &a); err != nil {
		t.Fatal(err)
	}
	if !a.OK || a.Credential == "" {
		t.Fatalf("enrollment failed: %+v", a)
	}
	if err := writeFrame(stream, registration{Exposes: []registeredExpose{{ID: "hello", Path: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := readFrame(stream, &a); err != nil {
		t.Fatal(err)
	}
	if !a.OK {
		t.Fatalf("registration rejected: %s", a.Error)
	}
}

func TestClientStoresEnrollmentCredential(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer local.Close()

	srv := NewServer(ServerConfig{
		Name:        "agents",
		BaseDomain:  "relay.test",
		Listen:      "127.0.0.1:0",
		TLSConfig:   testTLS(t),
		EnrollToken: "enroll-secret",
		Policy: alaye.RelayPolicy{
			AllowHTTP: true,
		},
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	exposes := []alaye.Expose{{
		ID:        "hello",
		Via:       "default",
		Path:      true,
		LocalPath: "/",
		LocalHost: "local.test",
	}}
	saved := ""
	ctx, cancel := context.WithCancel(context.Background())
	first := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Enroll:   "enroll-secret",
		Local:    local.URL,
		Insecure: true,
		Pool:     1,
		Exposes:  exposes,
		SaveCredential: func(v string) error {
			saved = v
			return nil
		},
	})
	go first.Run(ctx)

	waitRelayReady(t, srv, "relay.test", "/hello", "ok")
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for saved == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if saved == "" {
		t.Fatal("credential was not saved")
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	second := NewClient(ClientConfig{
		Agent:    "alice",
		Relay:    "https://" + srv.Addr(),
		Local:    local.URL,
		Insecure: true,
		Pool:     1,
		Exposes:  exposes,
		LoadCredential: func() string {
			return saved
		},
	})
	go second.Run(ctx2)
	waitRelayReady(t, srv, "relay.test", "/hello", "ok")
}

func waitRelayReady(t *testing.T, srv *Server, host, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
		req.Host = host
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK && strings.Contains(rr.Body.String(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not become ready, last status %d body %q", rr.Code, rr.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
