package relay

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/oshodi"
	"github.com/hashicorp/yamux"
	"github.com/olekukonko/ll"
)

var relayIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var relayReservedIDs = map[string]bool{
	"admin": true, "api": true, "www": true, "mail": true,
	"relay": true, "_agbero": true, "well-known": true,
}

// ServerConfig describes one remote relay listener.
type ServerConfig struct {
	Name            string
	BaseDomain      string
	Listen          string
	TLSConfig       *tls.Config
	AuthMethod      string
	EnrollToken     string
	EnrollTokenFunc func() string
	Policy          alaye.RelayPolicy
	Logger          *ll.Logger
	DB              *oshodi.DB
	// RegisterHost and UnregisterHost let the remote create the ephemeral
	// host entry needed for TLS and request matching on {id}.{base}.
	RegisterHost   func(domain string)
	UnregisterHost func(domain string)
}

// Server accepts agent connections and proxies registered HTTP paths through
// them. It is deliberately independent of the normal host router so a relay
// host does not need a route block per exposed path.
type Server struct {
	cfg    ServerConfig
	logger *ll.Logger

	mu       sync.RWMutex
	sessions map[string]*session
	routes   map[string]*route

	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
	wg     sync.WaitGroup

	tcpListeners map[int]*tcpListener
	udpListeners map[int]*udpListener

	startedAt   time.Time
	authErrors  atomic.Int64
	lastError   string
	lastErrorAt time.Time
	lastAuth    *AuthFailure
	reconnects  map[string]int64
	history     map[string][]SessionEvent

	store  *oshodi.Bucket
	agents *agentStore
}

type tcpListener struct {
	ln      net.Listener
	port    int
	target  string
	session *session
}

type udpListener struct {
	pc      net.PacketConn
	port    int
	target  string
	session *session
	mu      sync.Mutex
	clients map[string]*udpClient
}

type udpClient struct {
	addr   net.Addr
	tunnel net.Conn
}

type session struct {
	agent       string
	control     net.Conn
	remote      string
	connectedAt time.Time
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	lastError   string
	lastErrorAt time.Time
	mux         *yamux.Session
	mu          sync.Mutex
	streams     int
	maxStreams  int
	done        chan struct{}
	once        sync.Once
	reg         registration
}

type route struct {
	id        string
	path      string
	domain    string
	subdomain bool
	localPath string
	localHost string
	proxy     *httputil.ReverseProxy
	session   *session
}

// NewServer constructs a relay server. It does not listen until Start is called.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logger == nil {
		cfg.Logger = ll.New("relay").Disable()
	}
	var store *oshodi.Bucket
	if cfg.DB != nil {
		if b, err := cfg.DB.Bucket("relay_routes"); err == nil {
			store = b
		}
	}
	return &Server{
		cfg:          cfg,
		logger:       cfg.Logger.Namespace("relay"),
		sessions:     make(map[string]*session),
		routes:       make(map[string]*route),
		done:         make(chan struct{}),
		tcpListeners: make(map[int]*tcpListener),
		udpListeners: make(map[int]*udpListener),
		store:        store,
		agents:       newAgentStore(cfg.DB),
		reconnects:   make(map[string]int64),
		history:      make(map[string][]SessionEvent),
	}
}

func (s *Server) Start() error {
	if s.cfg.TLSConfig == nil {
		return fmt.Errorf("relay %q: TLS config is required", s.cfg.Name)
	}
	ln, err := tls.Listen("tcp", s.cfg.Listen, s.cfg.TLSConfig)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.ln = ln
	s.cancel = cancel
	s.startedAt = time.Now().UTC()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx)
	}()
	s.logger.Fields("relay", s.cfg.Name, "listen", s.cfg.Listen, "domain", s.cfg.BaseDomain).Info("relay listener started")
	return nil
}

// Addr returns the listener address, or an empty string before Start.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Server) registerHost(domain string) {
	if s.cfg.RegisterHost != nil {
		s.cfg.RegisterHost(domain)
	}
}

func (s *Server) unregisterHost(domain string) {
	if s.cfg.UnregisterHost != nil {
		s.cfg.UnregisterHost(domain)
	}
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.mu.Lock()
	for port, tl := range s.tcpListeners {
		_ = tl.ln.Close()
		delete(s.tcpListeners, port)
	}
	for port, ul := range s.udpListeners {
		_ = ul.pc.Close()
		ul.closeClients()
		delete(s.udpListeners, port)
	}
	s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
	s.mu.Lock()
	domains := make([]string, 0)
	for _, rt := range s.routes {
		if rt.subdomain {
			domains = append(domains, rt.domain)
		}
	}
	for _, sess := range s.sessions {
		sess.bye("relay shutting down")
	}
	for _, sess := range s.sessions {
		sess.close()
	}
	s.sessions = make(map[string]*session)
	s.routes = make(map[string]*route)
	s.mu.Unlock()
	for _, domain := range domains {
		s.unregisterHost(domain)
	}
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.logger.Fields("relay", s.cfg.Name, "err", err).Warn("relay accept failed")
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	head, err := br.Peek(len(muxMagic))
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	if string(head) == muxMagic {
		_, _ = br.Discard(len(muxMagic))
		mux, err := yamux.Server(&muxConn{Conn: conn, r: br}, newMuxConfig())
		if err != nil {
			s.logger.Fields("relay", s.cfg.Name, "err", err).Warn("relay mux handshake failed")
			_ = conn.Close()
			return
		}
		s.handleMux(ctx, conn, mux)
		return
	}
	s.handleRaw(conn, br)
}

// handleMux accepts the single control stream of a muxed agent connection.
// Work streams are opened by the relay from the same yamux session.
func (s *Server) handleMux(ctx context.Context, raw net.Conn, mux *yamux.Session) {
	defer mux.Close()
	stream, err := mux.AcceptStream()
	if err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	var h hello
	if err := readFrame(stream, &h); err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	if h.Kind != frameControl {
		_ = writeFrame(stream, ack{Error: "control stream required"})
		return
	}
	if !relayIDPattern.MatchString(h.Agent) || relayReservedIDs[h.Agent] {
		_ = writeFrame(stream, ack{Error: "invalid agent id"})
		return
	}
	credential, err := s.authenticate(h)
	if err != nil {
		_ = writeFrame(stream, ack{Error: err.Error()})
		return
	}
	if err := writeFrame(stream, controlAck(credential)); err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	var reg registration
	if err := readFrame(stream, &reg); err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	s.handleControl(ctx, stream, mux, raw.RemoteAddr().String(), h.Agent, reg)
}

// handleRaw serves the pre-mux check protocol. Old agents that still use data
// connections get an explicit upgrade error instead of hanging.
func (s *Server) handleRaw(conn net.Conn, r io.Reader) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var h hello
	if err := readFrame(r, &h); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if h.Kind == frameCheck {
		expected := s.cfg.EnrollToken
		if s.cfg.EnrollTokenFunc != nil {
			expected = s.cfg.EnrollTokenFunc()
		}
		ok := false
		if h.EnrollToken != "" {
			ok = subtle.ConstantTimeCompare([]byte(h.EnrollToken), []byte(expected)) == 1
		} else if h.Token != "" {
			ok = s.agents.verifyCredential(h.Agent, h.Token)
		}
		if ok {
			// An authenticated check also gets the relay's view of the agent so
			// the agent host can diagnose the tunnel without the admin API.
			// Relays that predate this send a bare ack, which old and new
			// doctors both accept.
			_ = writeFrame(conn, ack{OK: true, Session: s.sessionReport(h.Agent)})
		} else {
			_ = writeFrame(conn, ack{Error: "authentication failed"})
		}
		return
	}
	_ = writeFrame(conn, ack{Error: "relay protocol requires mux; rebuild the agent"})
}

func (s *Server) authenticate(h hello) (string, error) {
	if h.EnrollToken != "" {
		expected := s.cfg.EnrollToken
		if s.cfg.EnrollTokenFunc != nil {
			expected = s.cfg.EnrollTokenFunc()
		}
		issued, err := s.agents.enroll(h.Agent, h.EnrollToken, expected, s.cfg.Policy.MaxAgents)
		if err != nil {
			s.authErrors.Add(1)
			s.noteError(err.Error())
			return "", err
		}
		return issued, nil
	}
	if !s.agents.verifyCredential(h.Agent, h.Token) {
		s.authErrors.Add(1)
		s.noteError(errAuth.Error())
		return "", errAuth
	}
	return "", nil
}

// controlAck builds the acknowledgement sent on the control stream. The
// advertised heartbeat lets a new agent keep the connection alive through NATs
// and firewalls; agents that predate it ignore the field.
func controlAck(credential string) ack {
	return ack{OK: true, Credential: credential, HeartbeatSeconds: int(controlHeartbeat / time.Second)}
}

func (s *Server) handleControl(ctx context.Context, conn net.Conn, mux *yamux.Session, remote, agent string, reg registration) {
	sess := &session{
		agent:       agent,
		control:     conn,
		mux:         mux,
		remote:      remote,
		connectedAt: time.Now().UTC(),
		maxStreams:  s.cfg.Policy.MaxStreams,
		done:        make(chan struct{}),
	}
	s.mu.Lock()
	if _, seen := s.reconnects[agent]; seen {
		s.reconnects[agent]++
	} else {
		s.reconnects[agent] = 0
	}
	if old := s.sessions[agent]; old != nil {
		s.recordEventLocked(agent, SessionEvent{Kind: "replaced", Remote: old.remote,
			Reason: "replaced by a new session from " + remote})
		old.bye("session replaced")
		old.close()
	}
	s.sessions[agent] = sess
	s.recordEventLocked(agent, SessionEvent{Kind: "opened", Remote: remote})
	s.mu.Unlock()

	if err := s.applyRegistration(sess, reg); err != nil {
		_ = writeFrame(conn, ack{Error: err.Error()})
		s.mu.Lock()
		if s.sessions[agent] == sess {
			delete(s.sessions, agent)
		}
		s.mu.Unlock()
		sess.close()
		return
	}
	if err := writeFrame(conn, controlAck("")); err != nil {
		sess.close()
		return
	}

	reason := "control connection closed"
	defer func() {
		s.recordEvent(agent, SessionEvent{Kind: "closed", Remote: sess.remote, Reason: reason})
		s.logger.Fields("relay", s.cfg.Name, "agent", agent, "remote", sess.remote,
			"duration", time.Since(sess.connectedAt).Round(time.Millisecond),
			"reason", reason).Info("relay agent session closed")
	}()
	s.logger.Fields("relay", s.cfg.Name, "agent", agent, "remote", sess.remote).Info("relay agent session opened")

	for {
		var next registration
		if err := readFrame(conn, &next); err != nil {
			reason = err.Error()
			break
		}
		if next.Kind == framePing {
			// Heartbeat: answer so the agent also sees traffic, but never
			// treat it as a registration, which would drop the exposures.
			if err := writeFrame(conn, controlAck("")); err != nil {
				break
			}
			continue
		}
		if err := s.applyRegistration(sess, next); err != nil {
			_ = writeFrame(conn, ack{Error: err.Error()})
			continue
		}
		if err := writeFrame(conn, controlAck("")); err != nil {
			reason = "write failed: " + err.Error()
			break
		}
	}

	s.mu.Lock()
	current := s.sessions[agent] == sess
	if current {
		delete(s.sessions, agent)
	}
	var domains []string
	for key, rt := range s.routes {
		if rt.session == sess {
			delete(s.routes, key)
			if rt.subdomain {
				domains = append(domains, rt.domain)
			}
		}
	}
	// A reconnected agent replaces its session before this cleanup runs. In
	// that case the new session owns the persisted record, so the old one must
	// not overwrite it with an inactive snapshot.
	if current {
		s.persistLocked(sess.agent, sess.reg, false)
	}
	s.mu.Unlock()
	s.closeTCPForSession(sess)
	s.closeUDPForSession(sess)
	for _, domain := range domains {
		s.unregisterHost(domain)
	}
	sess.close()
}

func (s *Server) applyRegistration(sess *session, reg registration) error {
	for _, ex := range reg.Exposes {
		if err := s.validateExposure(ex); err != nil {
			return err
		}
	}

	keys := make([]string, 0, len(reg.Exposes)*3)
	for _, ex := range reg.Exposes {
		if ex.Path {
			keys = append(keys, "path:/"+ex.ID)
		}
		if ex.Subdomain {
			keys = append(keys, "sub:"+ex.ID)
		}
		if ex.TCPPort > 0 {
			keys = append(keys, fmt.Sprintf("tcp:%d", ex.TCPPort))
		}
		if ex.UDPPort > 0 {
			keys = append(keys, fmt.Sprintf("udp:%d", ex.UDPPort))
		}
	}
	if !s.agents.claim(sess.agent, keys) {
		return fmt.Errorf("relay: exposure is already owned by another agent")
	}

	s.mu.Lock()
	sess.reg = reg
	s.closeTCPForSessionLocked(sess)
	s.closeUDPForSessionLocked(sess)

	var removedDomains []string
	for key, rt := range s.routes {
		if rt.session == sess {
			delete(s.routes, key)
			if rt.subdomain {
				removedDomains = append(removedDomains, rt.domain)
			}
		}
	}

	for _, ex := range reg.Exposes {
		if ex.Path {
			prefix := "/" + ex.ID
			s.takeRouteLocked(sess, prefix, ex, prefix, false, "")
		}
		if ex.Subdomain {
			domain := ex.ID + "." + s.cfg.BaseDomain
			s.takeRouteLocked(sess, "sub:"+ex.ID, ex, "", true, domain)
		}
		if ex.TCPPort > 0 {
			s.startTCPLocked(sess, ex)
		}
		if ex.UDPPort > 0 {
			s.startUDPLocked(sess, ex)
		}
	}
	s.persistLocked(sess.agent, reg, true)
	s.agents.setExposures(sess.agent, reg.Exposes)
	s.mu.Unlock()

	for _, domain := range removedDomains {
		s.unregisterHost(domain)
	}
	s.mu.RLock()
	domains := make([]string, 0)
	for _, rt := range s.routes {
		if rt.session == sess && rt.subdomain {
			domains = append(domains, rt.domain)
		}
	}
	s.mu.RUnlock()
	for _, domain := range domains {
		s.registerHost(domain)
	}
	return nil
}

// takeRouteLocked installs the route owned by an exposure. Callers must hold
// s.mu.
//
// A previous control connection of the same agent can still own the route while
// its cleanup is running in another goroutine. Leaving that route in place
// would bind public requests to a dead session: they fail with 502, and the
// route disappears when the dead session is cleaned up, so later requests get
// 404. The new session takes the route over instead.
func (s *Server) takeRouteLocked(sess *session, key string, ex registeredExpose, prefix string, subdomain bool, domain string) {
	if rt, exists := s.routes[key]; exists {
		if rt.session == sess {
			return
		}
		if rt.session != nil && rt.session.agent != sess.agent {
			// Another agent owns the key; claims were checked before we got
			// here, so this is only defensive.
			return
		}
		delete(s.routes, key)
	}
	s.routes[key] = s.newRoute(sess, ex, prefix, subdomain, domain)
}

// noteError records the most recent server-side failure with its time, so the
// admin and the CLI check can tell a live failure from a historical one.
func (s *Server) noteError(msg string) {
	s.mu.Lock()
	s.lastError = msg
	s.lastErrorAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *Server) recordAuth(agent, mode, presented, expected, reason string) {
	s.mu.Lock()
	s.lastError = reason
	s.lastErrorAt = time.Now().UTC()
	s.lastAuth = &AuthFailure{
		Agent: agent, Mode: mode, Presented: fingerprint(presented),
		Expected: fingerprint(expected), Reason: reason, At: time.Now().UTC(),
	}
	s.mu.Unlock()
}

func (s *Server) validateExposure(ex registeredExpose) error {
	if !relayIDPattern.MatchString(ex.ID) || relayReservedIDs[ex.ID] {
		return fmt.Errorf("relay: invalid or reserved expose id %q", ex.ID)
	}
	if ex.Path && !s.cfg.Policy.AllowHTTP {
		return fmt.Errorf("relay: http paths are disabled")
	}
	if ex.Subdomain && !s.cfg.Policy.AllowSubdomain {
		return fmt.Errorf("relay: subdomains are disabled")
	}
	if ex.TCPPort > 0 && !portAllowed(s.cfg.Policy.AllowTCPPorts, ex.TCPPort) {
		return fmt.Errorf("relay: tcp port %d is not allowed", ex.TCPPort)
	}
	if ex.UDPPort > 0 && !portAllowed(s.cfg.Policy.AllowUDPPorts, ex.UDPPort) {
		return fmt.Errorf("relay: udp port %d is not allowed", ex.UDPPort)
	}
	if !ex.Path && !ex.Subdomain && ex.TCPPort == 0 && ex.UDPPort == 0 {
		return fmt.Errorf("relay: expose %q has no mode", ex.ID)
	}
	return nil
}

type storedRegistration struct {
	Relay      string             `json:"relay"`
	BaseDomain string             `json:"base_domain"`
	Agent      string             `json:"agent"`
	Active     bool               `json:"active"`
	Exposes    []registeredExpose `json:"exposes"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

func (s *Server) persistLocked(agent string, reg registration, active bool) {
	if s.store == nil {
		return
	}
	key := []byte(s.cfg.BaseDomain + "/" + agent)
	if !active && len(reg.Exposes) == 0 {
		_ = s.store.Delete(key)
		return
	}
	rec := storedRegistration{
		Relay:      s.cfg.Name,
		BaseDomain: s.cfg.BaseDomain,
		Agent:      agent,
		Active:     active,
		Exposes:    reg.Exposes,
		UpdatedAt:  time.Now().UTC(),
	}
	data, err := json.Marshal(rec)
	if err == nil {
		_ = s.store.Set(key, data)
	}
}

func (s *Server) startTCPLocked(sess *session, ex registeredExpose) {
	if !portAllowed(s.cfg.Policy.AllowTCPPorts, ex.TCPPort) {
		s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "port", ex.TCPPort).Warn("relay tcp port rejected")
		return
	}
	host := "0.0.0.0"
	if h, _, err := net.SplitHostPort(s.cfg.Listen); err == nil && h != "" {
		host = h
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", ex.TCPPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "addr", addr, "err", err).Error("relay tcp listener failed")
		return
	}
	tl := &tcpListener{ln: ln, port: ex.TCPPort, target: ex.ID, session: sess}
	s.tcpListeners[ex.TCPPort] = tl
	go s.acceptTCP(tl)
	s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "port", ex.TCPPort).Info("relay tcp listener started")
}

func (s *Server) acceptTCP(tl *tcpListener) {
	for {
		conn, err := tl.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			tunnel, err := tl.session.openWork(ctx, tl.target)
			cancel()
			if err != nil {
				_ = conn.Close()
				return
			}
			defer tunnel.Close()
			defer conn.Close()
			done := make(chan struct{}, 2)
			go func() {
				n, _ := io.Copy(tunnel, conn)
				tl.session.bytesIn.Add(n)
				done <- struct{}{}
			}()
			go func() {
				n, _ := io.Copy(conn, tunnel)
				tl.session.bytesOut.Add(n)
				done <- struct{}{}
			}()
			select {
			case <-done:
			case <-s.done:
			}
		}()
	}
}

func (s *Server) closeTCPForSessionLocked(sess *session) {
	for port, tl := range s.tcpListeners {
		if tl.session == sess {
			_ = tl.ln.Close()
			delete(s.tcpListeners, port)
		}
	}
}

func (s *Server) closeTCPForSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for port, tl := range s.tcpListeners {
		if tl.session == sess {
			_ = tl.ln.Close()
			delete(s.tcpListeners, port)
		}
	}
}

func portAllowed(ranges []string, port int) bool {
	for _, raw := range ranges {
		parts := strings.Split(strings.TrimSpace(raw), "-")
		if len(parts) == 0 {
			continue
		}
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}
		}
		if port >= start && port <= end {
			return true
		}
	}
	return false
}

func (s *Server) startUDPLocked(sess *session, ex registeredExpose) {
	if !portAllowed(s.cfg.Policy.AllowUDPPorts, ex.UDPPort) {
		s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "port", ex.UDPPort).Warn("relay udp port rejected")
		return
	}
	host := "0.0.0.0"
	if h, _, err := net.SplitHostPort(s.cfg.Listen); err == nil && h != "" {
		host = h
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", ex.UDPPort))
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "addr", addr, "err", err).Error("relay udp listener failed")
		return
	}
	ul := &udpListener{pc: pc, port: ex.UDPPort, target: ex.ID, session: sess, clients: make(map[string]*udpClient)}
	s.udpListeners[ex.UDPPort] = ul
	go s.serveUDP(ul)
	s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "port", ex.UDPPort).Info("relay udp listener started")
}

func (s *Server) serveUDP(ul *udpListener) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := ul.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		key := addr.String()
		ul.mu.Lock()
		client := ul.clients[key]
		ul.mu.Unlock()

		if client == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			tunnel, err := ul.session.openWork(ctx, ul.target)
			cancel()
			if err != nil {
				continue
			}
			ul.mu.Lock()
			if existing := ul.clients[key]; existing != nil {
				_ = tunnel.Close()
				client = existing
			} else {
				client = &udpClient{addr: addr, tunnel: tunnel}
				ul.clients[key] = client
				go ul.readUDP(client)
			}
			ul.mu.Unlock()
		}

		if err := writeDatagram(client.tunnel, buf[:n]); err != nil {
			ul.remove(client)
		} else {
			ul.session.bytesIn.Add(int64(n))
		}
	}
}

func (ul *udpListener) readUDP(client *udpClient) {
	for {
		payload, err := readDatagram(client.tunnel)
		if err != nil {
			ul.remove(client)
			return
		}
		ul.session.bytesOut.Add(int64(len(payload)))
		if _, err := ul.pc.WriteTo(payload, client.addr); err != nil {
			ul.remove(client)
			return
		}
	}
}

func (ul *udpListener) remove(client *udpClient) {
	ul.mu.Lock()
	if ul.clients[client.addr.String()] == client {
		delete(ul.clients, client.addr.String())
	}
	ul.mu.Unlock()
	_ = client.tunnel.Close()
}

func (ul *udpListener) closeClients() {
	ul.mu.Lock()
	defer ul.mu.Unlock()
	for _, c := range ul.clients {
		_ = c.tunnel.Close()
	}
	ul.clients = make(map[string]*udpClient)
}

func (s *Server) closeUDPForSessionLocked(sess *session) {
	for port, ul := range s.udpListeners {
		if ul.session == sess {
			_ = ul.pc.Close()
			ul.closeClients()
			delete(s.udpListeners, port)
		}
	}
}

func (s *Server) closeUDPForSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeUDPForSessionLocked(sess)
}

func (s *Server) newRoute(sess *session, ex registeredExpose, prefix string, subdomain bool, domain string) *route {
	localPath := ex.LocalPath
	if localPath == "" {
		localPath = "/"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sess.openWork(ctx, ex.ID)
		},
		DisableKeepAlives: true,
	}
	proxy := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "relay.local"
			suffix := pr.In.URL.Path
			if prefix != "" {
				suffix = strings.TrimPrefix(suffix, prefix)
			}
			pr.Out.URL.Path = joinPath(localPath, suffix)
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			if ex.LocalHost != "" {
				pr.Out.Host = ex.LocalHost
			} else {
				pr.Out.Host = pr.In.Host
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.logger.Fields("relay", s.cfg.Name, "agent", sess.agent, "err", err).Warn("relay proxy failed")
			s.noteError(fmt.Sprintf("%s %s: %v", r.Method, r.URL.Path, err))
			sess.mu.Lock()
			sess.lastError = err.Error()
			sess.lastErrorAt = time.Now().UTC()
			sess.mu.Unlock()
			s.recordEvent(sess.agent, SessionEvent{Kind: "proxy_error", Remote: sess.remote, Reason: err.Error()})
			http.Error(w, "Relay unavailable", http.StatusBadGateway)
		},
	}
	return &route{
		id: ex.ID, path: prefix, domain: domain, subdomain: subdomain,
		localPath: localPath, localHost: ex.LocalHost,
		proxy: proxy, session: sess,
	}
}

func joinPath(base, suffix string) string {
	if base == "" {
		base = "/"
	}
	if suffix == "" {
		suffix = "/"
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func (s *Server) match(r *http.Request) *route {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	base := strings.ToLower(strings.TrimSpace(s.cfg.BaseDomain))

	if host != base {
		suffix := "." + base
		if !strings.HasSuffix(host, suffix) {
			return nil
		}
		id := strings.TrimSuffix(host, suffix)
		if !relayIDPattern.MatchString(id) {
			return nil
		}
		s.mu.RLock()
		rt := s.routes["sub:"+id]
		s.mu.RUnlock()
		return rt
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *route
	for key, rt := range s.routes {
		if rt.subdomain {
			continue
		}
		if r.URL.Path == key || strings.HasPrefix(r.URL.Path, key+"/") {
			if best == nil || len(key) > len(best.path) {
				best = rt
			}
		}
	}
	return best
}

// Matches reports whether this relay handles the request.
func (s *Server) Matches(r *http.Request) bool { return s.match(r) != nil }

// ServeHTTP proxies a matched request through the agent.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt := s.match(r)
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	cw := &countingWriter{ResponseWriter: w}
	rt.proxy.ServeHTTP(cw, r)
	rt.session.bytesOut.Add(cw.n)
	if r.ContentLength > 0 {
		rt.session.bytesIn.Add(r.ContentLength)
	}
}

func (s *session) openWork(ctx context.Context, expose string) (net.Conn, error) {
	if s.closed() {
		return nil, errSessionClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.maxStreams > 0 && s.streams >= s.maxStreams {
		s.mu.Unlock()
		return nil, errStreamLimit
	}
	s.streams++
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		s.streams--
		s.mu.Unlock()
	}
	if s.mux == nil {
		release()
		return nil, errSessionClosed
	}
	stream, err := s.mux.OpenStream()
	if err != nil {
		release()
		return nil, err
	}
	ts := &trackedStream{Stream: stream, onClose: release}
	if err := writeFrame(ts, workHello{Kind: frameWork, Expose: expose}); err != nil {
		_ = ts.Close()
		return nil, err
	}
	return ts, nil
}

var (
	errSessionClosed = fmt.Errorf("relay: session closed")
	errStreamLimit   = fmt.Errorf("relay: stream limit reached")
)

// bye tells the agent why the relay is closing the session. A clean close or a
// replacement is visible on the agent as a reason; a crash or a dead path shows
// up as a bare EOF, which distinguishes the two cases.
func (s *session) bye(reason string) {
	if s.control == nil {
		return
	}
	_ = s.control.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeFrame(s.control, ack{Error: "relay: " + reason})
	_ = s.control.SetWriteDeadline(time.Time{})
}

// closed reports whether the session has been shut down, which can happen
// before it is replaced in the server's session map.
func (s *session) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		if s.mux != nil {
			_ = s.mux.Close()
		}
		if s.control != nil {
			_ = s.control.Close()
		}
	})
}

type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	return h.Hijack()
}
