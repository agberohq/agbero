package relay

import (
	"bufio"
	"io"
	"net"
	"sync"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/hashicorp/yamux"
)

// muxMagic prefixes the yamux handshake so a relay can keep serving the check
// protocol on the same port while agents negotiate the muxed protocol.
const muxMagic = def.RelayMuxMagic

func newMuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = def.RelayMuxAcceptBacklog
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = def.RelayMuxKeepAlive
	cfg.ConnectionWriteTimeout = def.RelayMuxWriteTimeout
	// A stream carries a whole HTTP request/response; the default window
	// throttles uploads and large bodies.
	cfg.MaxStreamWindowSize = def.RelayMuxStreamWindow
	cfg.StreamOpenTimeout = def.RelayMuxStreamOpen
	cfg.StreamCloseTimeout = def.RelayMuxStreamClose
	cfg.LogOutput = io.Discard
	return cfg
}

// muxConn replays the bytes a bufio.Reader already buffered while the magic
// was detected; yamux must see them as the start of its session.
type muxConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *muxConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// trackedStream counts a work stream against the session limit and releases it
// exactly once, whether it was closed by us or by the peer.
type trackedStream struct {
	*yamux.Stream
	once    sync.Once
	onClose func()
}

func (s *trackedStream) Close() error {
	err := s.Stream.Close()
	s.once.Do(s.onClose)
	return err
}
