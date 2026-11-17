// Package anchor provides a single-owner broker for resources that cannot be
// opened by multiple processes safely. The first successful owner serves typed
// JSON calls over a Unix socket; other processes attach or wait.
package anchor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type Role string

const (
	RoleService Role = "service"
	RoleCLI     Role = "cli"
	RoleAnchor  Role = "anchor"
)

type Options struct {
	Exclusive bool
	Role      Role
	Wait      time.Duration
}

type Handler interface {
	Handle(method string, params json.RawMessage) (any, error)
}

type HandlerFunc func(method string, params json.RawMessage) (any, error)

func (f HandlerFunc) Handle(method string, params json.RawMessage) (any, error) {
	return f(method, params)
}

type Anchor struct {
	Name string
	Dir  string
}

type Owner struct {
	anchor *Anchor
	ln     net.Listener
	client *Client
	once   sync.Once
}

type Client struct {
	conn net.Conn
	mu   sync.Mutex
	enc  *json.Encoder
	dec  *json.Decoder
}

type request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID    uint64          `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type ownerFile struct {
	PID   int    `json:"pid"`
	Role  Role   `json:"role"`
	Since string `json:"since"`
}

func New(name, dir string) *Anchor {
	return &Anchor{Name: name, Dir: dir}
}

func (a *Anchor) ownerPath() string { return filepath.Join(a.Dir, a.Name+".owner") }
func (a *Anchor) endpoint() string  { return endpointPath(a.Dir, a.Name) }

// Open attaches to an existing owner, or becomes the owner when none exists.
// The returned release function is safe to call more than once.
func (a *Anchor) Open(ctx context.Context, opts Options, h Handler) (*Client, func(), bool, error) {
	if opts.Role == "" {
		opts.Role = RoleCLI
	}
	if opts.Wait < 0 {
		opts.Wait = 0
	}

	c, err := a.dial()
	if err == nil {
		if opts.Exclusive {
			role := a.readRole()
			if role == RoleCLI && opts.Wait > 0 {
				_ = c.Close()
				if err := a.waitForFree(ctx, opts.Wait); err != nil {
					return nil, nil, false, err
				}
				return a.becomeOwner(opts, h)
			}
			_ = c.Close()
			return nil, nil, false, fmt.Errorf("anchor %q is already owned by %s", a.Name, role)
		}
		return c, func() { _ = c.Close() }, false, nil
	}

	if opts.Exclusive {
		role := a.readRole()
		if role == RoleCLI && opts.Wait > 0 {
			if err := a.waitForFree(ctx, opts.Wait); err != nil {
				return nil, nil, false, err
			}
		} else if role != "" {
			return nil, nil, false, fmt.Errorf("anchor %q is already owned by %s", a.Name, role)
		}
	}
	return a.becomeOwner(opts, h)
}

func (a *Anchor) becomeOwner(opts Options, h Handler) (*Client, func(), bool, error) {
	if err := os.MkdirAll(a.Dir, 0700); err != nil {
		return nil, nil, false, err
	}
	ln, err := listenEndpoint(a.endpoint())
	if err != nil {
		// A crashed owner can leave a socket inode behind. If the endpoint is
		// not accepting connections, remove it and retry the bind once.
		cleanupEndpoint(a.endpoint())
		ln, err = listenEndpoint(a.endpoint())
		if err != nil {
			if c, dialErr := a.dial(); dialErr == nil {
				return c, func() { _ = c.Close() }, false, nil
			}
			return nil, nil, false, err
		}
	}
	secureEndpoint(a.endpoint())
	owner := ownerFile{PID: os.Getpid(), Role: opts.Role, Since: time.Now().UTC().Format(time.RFC3339)}
	if data, err := json.Marshal(owner); err == nil {
		_ = os.WriteFile(a.ownerPath(), data, 0600)
	}
	o := &Owner{anchor: a, ln: ln}
	go o.serve(h)
	client, err := a.dial()
	if err != nil {
		o.Close()
		return nil, nil, false, err
	}
	o.client = client
	return client, o.Close, true, nil
}

func (o *Owner) Close() {
	o.once.Do(func() {
		if o.client != nil {
			_ = o.client.Close()
		}
		if o.ln != nil {
			_ = o.ln.Close()
		}
		cleanupEndpoint(o.anchor.endpoint())
		_ = os.Remove(o.anchor.ownerPath())
	})
}

func (o *Owner) serve(h Handler) {
	for {
		conn, err := o.ln.Accept()
		if err != nil {
			return
		}
		go serveConn(conn, h)
	}
}

func serveConn(conn net.Conn, h Handler) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			return
		}
		var resp response
		resp.ID = req.ID
		if h == nil {
			resp.Error = "no handler"
			_ = enc.Encode(resp)
			continue
		}
		value, err := h.Handle(req.Method, req.Params)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			if value != nil {
				data, err := json.Marshal(value)
				if err != nil {
					resp.Error = err.Error()
				} else {
					resp.Value = data
				}
			}
		}
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (a *Anchor) dial() (*Client, error) {
	conn, err := dialEndpoint(a.endpoint(), 250*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}, nil
}

func (a *Anchor) waitForFree(ctx context.Context, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		if a.readRole() == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("anchor %q is still owned by %s", a.Name, a.readRole())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (a *Anchor) readRole() Role {
	data, err := os.ReadFile(a.ownerPath())
	if err != nil {
		return ""
	}
	var o ownerFile
	if json.Unmarshal(data, &o) != nil {
		return ""
	}
	return o.Role
}

func (c *Client) Call(ctx context.Context, method string, params, reply any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	var raw json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = data
	}
	if err := c.enc.Encode(request{ID: 1, Method: method, Params: raw}); err != nil {
		return err
	}
	var resp response
	if err := c.dec.Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if reply != nil && len(resp.Value) > 0 {
		return json.Unmarshal(resp.Value, reply)
	}
	return nil
}

func (c *Client) Close() error { return c.conn.Close() }

func PathFor(dir, name string) string { return endpointPath(dir, name) }
func PID() string                     { return strconv.Itoa(os.Getpid()) }
