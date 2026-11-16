package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

// ClientConfig describes the local agent connection.
type ClientConfig struct {
	Agent          string
	Relay          string
	Enroll         string
	Token          string
	Local          string
	Insecure       bool
	Pool           int
	Exposes        []alaye.Expose
	LoadCredential func() string
	SaveCredential func(string) error
	Logger         *ll.Logger
}

// Client maintains an outbound connection to a remote relay and a pool of raw
// data connections. It never listens on a public interface.
type Client struct {
	cfg        ClientConfig
	logger     *ll.Logger
	credential string
}

// NewClient constructs a local relay agent.
func NewClient(cfg ClientConfig) *Client {
	if cfg.Logger == nil {
		cfg.Logger = ll.New("relay-agent").Disable()
	}
	if cfg.Pool <= 0 {
		cfg.Pool = 8
	}
	return &Client{cfg: cfg, logger: cfg.Logger.Namespace("relay-agent")}
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
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
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
	tlsCfg := &tls.Config{
		ServerName:         u.Hostname(),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.cfg.Insecure,
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	control, err := dialer.DialContext(ctx, "tcp", host)
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
	if credential == "" && c.cfg.Enroll == "" {
		return fmt.Errorf("relay credential is missing and no enrollment token is configured")
	}
	h := hello{Kind: frameControl, Agent: c.cfg.Agent, Token: credential}
	if credential == "" {
		h.EnrollToken = c.cfg.Enroll
	}
	if err := writeFrame(control, h); err != nil {
		return err
	}
	var authFrame ack
	if err := readFrame(control, &authFrame); err != nil {
		return err
	}
	if !authFrame.OK {
		if credential != "" && c.cfg.Enroll != "" {
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
	c.logger.Fields("agent", c.cfg.Agent, "relay", c.cfg.Relay).Info("relay agent connected")

	dataCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		var f ack
		_ = readFrame(control, &f)
		cancel()
	}()

	targets := map[string]string{"http": c.cfg.Local}
	for _, ex := range c.cfg.Exposes {
		if ex.TCP != nil {
			targets["tcp:"+ex.ID] = ex.TCP.Local
		}
		if ex.UDP != nil {
			targets["udp:"+ex.ID] = ex.UDP.Local
		}
	}
	for target, local := range targets {
		for i := 0; i < c.cfg.Pool; i++ {
			go c.dataLoop(dataCtx, target, local)
		}
	}
	<-dataCtx.Done()
	return nil
}

func (c *Client) dataLoop(ctx context.Context, target, local string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var err error
		if strings.HasPrefix(target, "udp:") {
			err = c.runUDPData(ctx, target, local)
		} else {
			err = c.runData(ctx, target, local)
		}
		if err != nil && ctx.Err() == nil {
			c.logger.Fields("agent", c.cfg.Agent, "err", err).Warn("relay data connection failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (c *Client) runUDPData(ctx context.Context, target, localAddr string) error {
	conn, err := c.dataConn(ctx, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	localConn, err := net.Dial("udp", localAddr)
	if err != nil {
		return err
	}
	defer localConn.Close()
	for {
		payload, err := readDatagram(conn)
		if err != nil {
			return err
		}
		if _, err := localConn.Write(payload); err != nil {
			return err
		}
		_ = localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 65535)
		n, err := localConn.Read(buf)
		if err != nil {
			return err
		}
		if err := writeDatagram(conn, buf[:n]); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

func (c *Client) dataConn(ctx context.Context, target string) (net.Conn, error) {
	u, err := url.Parse(c.cfg.Relay)
	if err != nil {
		return nil, err
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
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, hello{Kind: frameData, Agent: c.cfg.Agent, Token: c.credential, Target: target}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) runData(ctx context.Context, target, localAddr string) error {
	conn, err := c.dataConn(ctx, target)
	if err != nil {
		return err
	}
	defer conn.Close()

	targetAddr := localAddr
	if strings.HasPrefix(localAddr, "http://") || strings.HasPrefix(localAddr, "https://") {
		local, err := url.Parse(localAddr)
		if err != nil || local.Host == "" {
			return fmt.Errorf("invalid local URL")
		}
		targetAddr = local.Host
		if !strings.Contains(targetAddr, ":") {
			if local.Scheme == "https" {
				targetAddr += ":443"
			} else {
				targetAddr += ":80"
			}
		}
	}
	localConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	defer localConn.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(localConn, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, localConn); done <- struct{}{} }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
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
