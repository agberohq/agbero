// Package control provides the local, operation-oriented control channel used
// by the Agbero daemon and CLI. It is not a general-purpose file API.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
)

var (
	ErrUnavailable = errors.New("control: daemon is not running")
	ErrClosed      = errors.New("control: server closed")
)

// Handler executes one named operation.
type Handler func(context.Context, json.RawMessage) (any, error)

type request struct {
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type response struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Server is a local Unix-socket RPC server.
type Server struct {
	path string

	mu       sync.RWMutex
	handlers map[string]Handler

	ln        net.Listener
	quit      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewServer creates a server bound to path.
func NewServer(path string) *Server {
	return &Server{
		path:     path,
		handlers: make(map[string]Handler),
		quit:     make(chan struct{}),
	}
}

// Handle registers an operation. It must be called before Start.
func (s *Server) Handle(op string, h Handler) {
	s.mu.Lock()
	s.handlers[op] = h
	s.mu.Unlock()
}

// Start binds the socket and starts accepting connections.
func (s *Server) Start() error {
	if s.path == "" {
		return errors.New("control: socket path is required")
	}
	if err := prepareControlPath(s.path); err != nil {
		return fmt.Errorf("control: prepare socket: %w", err)
	}
	// A stale socket is safe to remove only when the caller owns the
	// authority lock. Try a quick dial first so a live owner is never unlinked.
	if c, err := dialControl(s.path, def.DefaultControlDialTimeout); err == nil {
		_ = c.Close()
		return errors.New("control: socket already has an owner")
	}
	_ = removeControlPath(s.path)
	ln, err := listenControl(s.path)
	if err != nil {
		return fmt.Errorf("control: listen: %w", err)
	}
	if err := secureControlPath(s.path); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control: secure socket: %w", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
		}()
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	if !peerAllowed(conn) {
		return
	}
	var req request
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return
	}
	resp := response{}
	s.mu.RLock()
	h := s.handlers[req.Op]
	s.mu.RUnlock()
	if h == nil {
		resp.Error = "unknown operation: " + req.Op
	} else {
		value, err := h(context.Background(), req.Payload)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			if value != nil {
				if b, err := json.Marshal(value); err == nil {
					resp.Payload = b
				} else {
					resp.OK = false
					resp.Error = err.Error()
				}
			}
		}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

// Close stops the server and removes its socket.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.quit)
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.wg.Wait()
		_ = removeControlPath(s.path)
	})
	return nil
}

// Client is a local control client.
type Client struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
}

// Dial connects to a running control server.
func Dial(path string) (*Client, error) {
	if path == "" {
		return nil, ErrUnavailable
	}
	conn, err := dialControl(path, def.DefaultControlDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Client{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}, nil
}

// DialRetry waits for the coordinator socket to appear, bounded by ctx.
func DialRetry(ctx context.Context, path string) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		c, err := Dial(path)
		if err == nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
		case <-time.After(def.DefaultControlRetryDelay):
		}
	}
}

// Call performs one operation and decodes its result into out.
func (c *Client) Call(ctx context.Context, op string, in any, out any) error {
	if c == nil || c.conn == nil {
		return ErrUnavailable
	}
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.conn.SetDeadline(deadline)
		}
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := c.enc.Encode(request{Op: op, Payload: payload}); err != nil {
		return err
	}
	var resp response
	if err := c.dec.Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "control: operation failed"
		}
		return errors.New(resp.Error)
	}
	if out != nil && len(resp.Payload) > 0 {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
