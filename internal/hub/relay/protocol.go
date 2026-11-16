package relay

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const maxFrameSize = 64 << 10

type frameKind string

const (
	frameControl      frameKind = "control"
	frameData         frameKind = "data"
	frameRegistration frameKind = "registration"
	frameAck          frameKind = "ack"
)

type hello struct {
	Kind        frameKind `json:"kind"`
	Agent       string    `json:"agent"`
	Token       string    `json:"token,omitempty"`
	EnrollToken string    `json:"enroll_token,omitempty"`
	Target      string    `json:"target,omitempty"`
}

type registration struct {
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

type ack struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Credential string `json:"credential,omitempty"`
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
