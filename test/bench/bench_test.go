// Package bench contains reproducible forwarding and lifecycle benchmarks.
//
// Run:
//
//	go test -bench . -benchmem ./test/bench
//
// These benchmarks are intentionally end-to-end where practical so lifecycle
// changes cannot hide behind mocks.
package bench

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/handlers/xtcp"
	"github.com/agberohq/agbero/internal/handlers/xudp"
	"github.com/agberohq/agbero/internal/hub/lifecycle"
	"github.com/agberohq/agbero/internal/hub/resource"
)

func BenchmarkLifecycleAdmitRelease(b *testing.B) {
	c := lifecycle.New()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !c.Admit() {
				b.Fatal("Admit failed")
			}
			c.Release()
		}
	})
}

func BenchmarkTCPProxyConnection(b *testing.B) {
	backend, closeBackend := startTCPBackend(b)
	defer closeBackend()

	proxyAddr := freeTCPAddr(b)
	p := xtcp.NewProxy(resource.New(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{Backends: []alaye.Server{alaye.NewServer(backend)}})
	if err := p.Start(); err != nil {
		b.Fatal(err)
	}
	defer p.Stop()
	waitTCP(b, proxyAddr)

	buf := make([]byte, 2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := net.DialTimeout("tcp", proxyAddr, time.Second)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			_ = c.Close()
			b.Fatal(err)
		}
		_ = c.Close()
	}
}

func BenchmarkUDPProxyPacket(b *testing.B) {
	backend, closeBackend := startUDPBackend(b)
	defer closeBackend()

	p := xudp.NewProxy(resource.New(), "127.0.0.1:0")
	p.AddRoute("", alaye.Proxy{Backends: []alaye.Server{alaye.NewServer(backend)}})
	if err := p.Start(); err != nil {
		b.Fatal(err)
	}
	defer p.Stop()

	c, err := net.Dial("udp", p.Listen)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	payload := []byte("ping")
	buf := make([]byte, len(payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func freeTCPAddr(tb testing.TB) string {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitTCP(tb testing.TB, addr string) {
	tb.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	tb.Fatalf("proxy %s did not become ready", addr)
}

func startTCPBackend(tb testing.TB) (string, func()) {
	tb.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("ok"))
			}(c)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		wg.Wait()
	}
}

func startUDPBackend(tb testing.TB) (string, func()) {
	tb.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		tb.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(buf[:n], addr)
		}
	}()
	return c.LocalAddr().String(), func() {
		_ = c.Close()
		<-done
	}
}
