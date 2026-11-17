package relay

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

const maxFrameSize = 64 << 10

type frameKind string

const (
	frameControl      frameKind = "control"
	frameCheck        frameKind = "check"
	frameRegistration frameKind = "registration"
	frameAck          frameKind = "ack"
	framePing         frameKind = "ping"
	frameWork         frameKind = "work"
)

// controlHeartbeat is the interval advertised to agents for control-channel
// pings. Idle control connections are otherwise torn down by NATs and
// firewalls that drop flows without payload traffic.
const controlHeartbeat = 25 * time.Second

type hello struct {
	Kind        frameKind `json:"kind"`
	Agent       string    `json:"agent"`
	Token       string    `json:"token,omitempty"`
	EnrollToken string    `json:"enroll_token,omitempty"`
}

type registration struct {
	// Kind is empty for a registration and framePing for a control heartbeat.
	// Relays that predate heartbeats ignore it and never receive pings because
	// the agent only sends them when a relay advertises an interval.
	Kind    frameKind          `json:"kind,omitempty"`
	Exposes []registeredExpose `json:"exposes"`
}

type registeredExpose struct {
	ID        string `json:"id"`
	Path      bool   `json:"path"`
	Subdomain bool   `json:"subdomain"`
	LocalPath string `json:"local_path,omitempty"`
	LocalHost string `json:"local_host,omitempty"`
	TCPPort   int    `json:"tcp_port,omitempty"`
	TCPLocal  string `json:"tcp_local,omitempty"`
	UDPPort   int    `json:"udp_port,omitempty"`
	UDPLocal  string `json:"udp_local,omitempty"`
}

// workHello is the first frame on a server-opened work stream. The agent uses
// the expose id to pick the local target; the relay has already rewritten the
// HTTP request (path and Host) before writing it to the stream.
type workHello struct {
	Kind   frameKind `json:"kind"`
	Expose string    `json:"expose,omitempty"`
	Host   string    `json:"host,omitempty"`
	Src    string    `json:"src,omitempty"`
}

type ack struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Credential string `json:"credential,omitempty"`
	// HeartbeatSeconds asks the agent to ping the control connection at this
	// interval. Zero means the relay does not require heartbeats.
	HeartbeatSeconds int `json:"heartbeat_seconds,omitempty"`
	// Session is the relay's view of the agent, sent only in reply to an
	// authenticated check.
	Session *SessionReport `json:"session,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > maxFrameSize {
		return fmt.Errorf("relay: frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrameSize {
		return fmt.Errorf("relay: invalid frame size %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeDatagram(w io.Writer, payload []byte) error {
	if len(payload) > 65535 {
		return fmt.Errorf("relay: datagram too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
