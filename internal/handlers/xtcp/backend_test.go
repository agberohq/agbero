package xtcp

import (
	"net"
	"testing"
	"time"
)

func TestConnPool_isAlive(t *testing.T) {
	// 1. Start a test listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// 2. Accept connection in goroutine and write greeting
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write "greeting" data immediately
		conn.Write([]byte("HELLO"))

		// Keep open for a bit, then close
		time.Sleep(200 * time.Millisecond)
	}()

	// 3. Client connects
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	// Wait for data to arrive in OS buffer
	time.Sleep(50 * time.Millisecond)

	pool := &connPool{}

	// TEST A: Check isAlive on a connection with data waiting
	if !pool.isAlive(conn) {
		t.Fatal("isAlive returned false, expected true (connection is open with data)")
	}

	// TEST B: Verify isAlive did NOT consume the data (MSG_PEEK check)
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read after isAlive: %v", err)
	}
	if n != 5 || string(buf) != "HELLO" {
		t.Errorf("isAlive consumed data! Got %q, expected 'HELLO'", string(buf[:n]))
	}

	// TEST C: Check isAlive on a closed connection
	time.Sleep(250 * time.Millisecond) // Wait for server to close

	// Read EOF to ensure local socket state is updated
	_, _ = conn.Read(make([]byte, 1))

	if pool.isAlive(conn) {
		t.Fatal("isAlive returned true, expected false (connection is closed)")
	}
}
