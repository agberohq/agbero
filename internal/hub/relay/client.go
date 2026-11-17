package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/hashicorp/yamux"
	"github.com/olekukonko/ll"
)

// ClientConfig describes the local agent connection.
type ClientConfig struct {
	Agent           string
	Relay           string
	Enroll          string
	EnrollTokenFunc func() string
	Token           string
	Local           string
	LocalSNI        string
	LocalInsecure   bool
	Insecure        bool
	Pool            int
	Exposes         []alaye.Expose
	LoadCredential  func() string
	SaveCredential  func(string) error
	Logger          *ll.Logger
}

// Client maintains an outbound connection to a remote relay and a pool of raw
// data connections. It never listens on a public interface.
type Client struct {
	cfg        ClientConfig
	logger     *ll.Logger
	credential string
	connects   atomic.Int64
	exposes    map[string]alaye.Expose
}

// NewClient constructs a local relay agent.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Logger == nil {
		cfg.Logger = ll.New("relay-agent").Disable()
	}
	if cfg.Pool <= 0 {
		cfg.Pool = 8
	}
	exposes := make(map[string]alaye.Expose, len(cfg.Exposes))
	for _, ex := range cfg.Exposes {
		exposes[ex.ID] = ex
	}
	return &Client{cfg: cfg, logger: cfg.Logger.Namespace("relay-agent"), exposes: exposes}
}

// Run connects and reconnects until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		before := c.connects.Load()
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if c.connects.Load() != before {
			// The session was established, so the next attempt should start
			// from the shortest delay instead of the largest one.
			backoff = time.Second
		}
		if err != nil {
			c.logger.Fields("agent", c.cfg.Agent, "err", err).Warn("relay connection failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	u, err := url.Parse(c.cfg.Relay)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid relay URL")
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         u.Hostname(),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.cfg.Insecure,
	}}
	raw, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	if _, err := raw.Write([]byte(muxMagic)); err != nil {
		_ = raw.Close()
		return err
	}
	mux, err := yamux.Client(raw, newMuxConfig())
	if err != nil {
		_ = raw.Close()
		return err
	}
	defer mux.Close()

	control, err := mux.OpenStream()
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(15 * time.Second))
	credential := c.credential
	if credential == "" {
		credential = c.cfg.Token
	}
	if credential == "" && c.cfg.LoadCredential != nil {
		credential = c.cfg.LoadCredential()
	}
	enrollToken := c.cfg.Enroll
	if c.cfg.EnrollTokenFunc != nil {
		enrollToken = c.cfg.EnrollTokenFunc()
	}
	if credential == "" && enrollToken == "" {
		return fmt.Errorf("relay credential is missing and no enrollment token is configured")
	}
	h := hello{Kind: frameControl, Agent: c.cfg.Agent, Token: credential}
	if credential == "" {
		h.EnrollToken = enrollToken
	}
	if err := writeFrame(control, h); err != nil {
		return err
	}
	var authFrame ack
	if err := readFrame(control, &authFrame); err != nil {
		return err
	}
	if !authFrame.OK {
		enrollAvailable := c.cfg.Enroll != "" || c.cfg.EnrollTokenFunc != nil
		if credential != "" && enrollAvailable {
			c.credential = ""
			if c.cfg.SaveCredential != nil {
				_ = c.cfg.SaveCredential("")
			}
		}
		return fmt.Errorf("relay authentication failed: %s", authFrame.Error)
	}
	if authFrame.Credential != "" {
		credential = authFrame.Credential
		if c.cfg.SaveCredential != nil {
			if err := c.cfg.SaveCredential(credential); err != nil {
				return fmt.Errorf("store relay credential: %w", err)
			}
		}
	}
	c.credential = credential

	if err := writeFrame(control, regFromExposes(c.cfg.Exposes)); err != nil {
		return err
	}
	var ackFrame ack
	if err := readFrame(control, &ackFrame); err != nil {
		return err
	}
	if !ackFrame.OK {
		return fmt.Errorf("relay rejected registration: %s", ackFrame.Error)
	}
	_ = control.SetDeadline(time.Time{})
	c.connects.Add(1)
	c.logger.Fields("agent", c.cfg.Agent, "relay", c.cfg.Relay).Info("relay agent connected")

	dataCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// Control frames are acknowledgements and heartbeat replies; only a
		// read error ends the session.
		for {
			var f ack
			if err := readFrame(control, &f); err != nil {
				c.logger.Fields("agent", c.cfg.Agent, "reason", err.Error()).Warn("relay control connection closed")
				cancel()
				return
			}
			if f.Error != "" {
				c.logger.Fields("agent", c.cfg.Agent, "reason", f.Error).Warn("relay control connection closed")
				cancel()
				return
			}
		}
	}()
	if ackFrame.HeartbeatSeconds > 0 {
		go c.heartbeat(dataCtx, control, time.Duration(ackFrame.HeartbeatSeconds)*time.Second)
	}
	go c.acceptLoop(dataCtx, mux)
	<-dataCtx.Done()
	return nil
}

// heartbeat keeps the control connection alive through NATs and firewalls that
// expire flows without payload traffic. A failed write closes the connection so
// the session is rebuilt instead of lingering as a half-open tunnel.
func (c *Client) heartbeat(ctx context.Context, control net.Conn, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := writeFrame(control, registration{Kind: framePing}); err != nil {
				_ = control.Close()
				return
			}
		}
	}
}

// acceptLoop serves streams the relay opens for a public request or connection.
func (c *Client) acceptLoop(ctx context.Context, mux *yamux.Session) {
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
			var h workHello
			if err := readFrame(stream, &h); err != nil {
				c.workFailed("", "read work header", err)
				return
			}
			_ = stream.SetReadDeadline(time.Time{})
			if h.Kind != frameWork {
				c.workFailed(h.Expose, "unexpected frame", fmt.Errorf("kind %q", h.Kind))
				return
			}
			c.handleWork(ctx, stream, h)
		}()
	}
}

func (c *Client) handleWork(ctx context.Context, stream net.Conn, h workHello) {
	ex, known := c.exposes[h.Expose]
	if h.Expose != "" && !known {
		c.workFailed(h.Expose, "unknown expose", fmt.Errorf("relay asked for an expose this agent does not register"))
		return
	}
	switch {
	case known && ex.TCP != nil && ex.TCP.Local != "":
		local, err := (&net.Dialer{}).DialContext(ctx, "tcp", ex.TCP.Local)
		if err != nil {
			c.workFailed(h.Expose, "dial tcp target "+ex.TCP.Local, err)
			return
		}
		defer local.Close()
		joinConns(local, stream)
	case known && ex.UDP != nil && ex.UDP.Local != "":
		c.runUDP(ctx, stream, ex.UDP.Local)
	default:
		c.serveHTTP(ctx, stream)
	}
}

// serveHTTP dials the local target lazily: the relay has already written the
// HTTP request to the stream, so the local connection is never idle.
func (c *Client) serveHTTP(ctx context.Context, stream net.Conn) {
	buf := make([]byte, 32<<10)
	n, err := stream.Read(buf)
	if n == 0 && err != nil {
		return
	}
	if err := ctx.Err(); err != nil {
		c.workFailed("", "session ended before the request was served", err)
		return
	}
	local, err := c.dialLocal(ctx, c.cfg.Local)
	if err != nil {
		c.workFailed("", "dial local target "+c.cfg.Local, err)
		return
	}
	defer local.Close()
	if _, err := local.Write(buf[:n]); err != nil {
		c.workFailed("", "write to local target", err)
		return
	}
	joinConns(local, stream)
}

// workFailed logs a work stream the agent closed without serving. The relay
// sees these as a bare EOF and answers 502, so this line is the only place the
// cause is visible.
func (c *Client) workFailed(expose, stage string, err error) {
	c.logger.Fields("agent", c.cfg.Agent, "expose", expose, "stage", stage, "err", err).Warn("relay work stream failed")
}

func (c *Client) runUDP(ctx context.Context, stream net.Conn, localAddr string) {
	local, err := net.Dial("udp", localAddr)
	if err != nil {
		return
	}
	defer local.Close()
	for {
		payload, err := readDatagram(stream)
		if err != nil {
			return
		}
		if _, err := local.Write(payload); err != nil {
			return
		}
		_ = local.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 65535)
		n, err := local.Read(buf)
		if err != nil {
			return
		}
		if err := writeDatagram(stream, buf[:n]); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func joinConns(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func isHTTPTarget(addr string) bool {
	lower := strings.ToLower(addr)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// dialLocal connects to the agent's local target.
func (c *Client) dialLocal(ctx context.Context, localAddr string) (net.Conn, error) {
	targetAddr := localAddr
	secure := false
	if isHTTPTarget(localAddr) {
		local, err := url.Parse(localAddr)
		if err != nil || local.Host == "" {
			return nil, fmt.Errorf("invalid local URL")
		}
		targetAddr = local.Host
		secure = local.Scheme == "https"
		if !strings.Contains(targetAddr, ":") {
			if secure {
				targetAddr += ":443"
			} else {
				targetAddr += ":80"
			}
		}
	}
	if secure {
		host, _, _ := net.SplitHostPort(targetAddr)
		if c.cfg.LocalSNI != "" {
			host = c.cfg.LocalSNI
		}
		d := &tls.Dialer{Config: &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: c.cfg.LocalInsecure,
		}}
		return d.DialContext(ctx, "tcp", targetAddr)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
}

func regFromExposes(exposes []alaye.Expose) registration {
	out := registration{Exposes: make([]registeredExpose, 0, len(exposes))}
	for _, ex := range exposes {
		re := registeredExpose{
			ID:        ex.ID,
			Path:      ex.Path,
			Subdomain: ex.Subdomain,
			LocalPath: ex.LocalPath,
			LocalHost: ex.LocalHost,
		}
		if ex.TCP != nil {
			re.TCPPort = ex.TCP.PublicPort
			re.TCPLocal = ex.TCP.Local
		}
		if ex.UDP != nil {
			re.UDPPort = ex.UDP.PublicPort
			re.UDPLocal = ex.UDP.Local
		}
		out.Exposes = append(out.Exposes, re)
	}
	return out
}
