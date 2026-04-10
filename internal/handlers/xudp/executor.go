package xudp

import (
	"bytes"
	"context"
	"net"
	"time"
)

// UDPExecutor implements health probing for UDP backends.
// It dials the backend with net.DialUDP, sends a probe payload,
// and checks the response against an expected prefix.
//
// For STUN backends use STUNBindingRequest as Send and the first
// two bytes of a Binding Success Response (0x01, 0x01) as Expect.
// For DNS backends send a minimal query and check for a valid response header.
// For generic backends, any non-empty response to a ping payload suffices.
type UDPExecutor struct {
	Address string
	Send    []byte // probe payload to send
	Expect  []byte // expected response prefix (nil = any non-empty response)
	Timeout time.Duration
}

// Probe dials the UDP backend, sends the probe, and reads one response.
// Returns (success, latency, error).
func (u *UDPExecutor) Probe(ctx context.Context) (bool, time.Duration, error) {
	start := time.Now()

	timeout := u.Timeout
	if timeout <= 0 {
		timeout = time.Duration(healthProbeTimeoutSeconds) * time.Second
	}

	// Use context deadline if tighter
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < timeout {
			timeout = remaining
		}
	}

	conn, err := net.DialTimeout("udp", u.Address, timeout)
	if err != nil {
		return false, time.Since(start), err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send probe payload
	if len(u.Send) > 0 {
		if _, err := conn.Write(u.Send); err != nil {
			return false, time.Since(start), err
		}
	}

	// Read one response datagram
	buf := getDatagram()
	defer putDatagram(buf)

	n, err := conn.Read(buf)
	latency := time.Since(start)
	if err != nil {
		return false, latency, err
	}

	// No expected prefix configured — any response means alive
	if len(u.Expect) == 0 {
		return n > 0, latency, nil
	}

	return bytes.HasPrefix(buf[:n], u.Expect), latency, nil
}
