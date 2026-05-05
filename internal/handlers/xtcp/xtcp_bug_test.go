package xtcp

import (
	"net"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/hub/resource"
)

func TestProxy_ReadDeadlineLeak_SlowClient(t *testing.T) {
	// Start a backend server that waits for client close before responding (half-close scenario)
	halfCloseAddr, stopHalfClose := startHalfCloseServer(t)
	defer stopHalfClose()

	// Create a proxy routing to that backend
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), proxyAddr)
	p.SetIdleTimeout(200 * time.Millisecond) // Short idle timeout for the test
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(halfCloseAddr)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, tcpReadyTimeout)

	// Number of malicious slow connections to simulate
	numSlowConns := 100

	// Establish multiple connections that never send data
	var conns []net.Conn
	for i := 0; i < numSlowConns; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, tcpDialTimeout)
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		conns = append(conns, conn)
		// Do NOT send data; just let the connection idle.
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	// Give the proxy time to accept and start handling connections
	time.Sleep(500 * time.Millisecond)

	// After the idle timeout, the proxy should have closed these connections
	// and reclaimed resources, but due to the missing ReadDeadline,
	// the goroutines are stuck reading from the dead client.
	// We can't directly count goroutines easily, but we can check if the proxy
	// keeps accumulating connections without releasing them.
	//
	// The BUG: deadlineConn.Read() does NOT set a read deadline,
	// so io.CopyBuffer blocks forever on a silent client.
	// This test indirectly proves the bug by showing that after the idle timeout,
	// the number of tracked connections (BackendCount) does not drop to zero.
	// In a fixed implementation, they would be cleaned up.

	currentConns := p.BackendCount()
	t.Logf("Active connections after idle timeout: %d", currentConns)

	if currentConns > 0 {
		t.Error("BUG CONFIRMED: Proxy should have cleaned up idle connections after timeout but didn't, indicating a read deadline leak")
	}

	// Note: Depending on OS and timing, this might still pass if the connections
	// are closed due to TCP keepalive or other OS-level timeouts, but the proxy
	// code itself is at fault for not setting the read deadline.
}
