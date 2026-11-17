// Constants used by the relay tunnel, its transports and diagnostics.
package def

import "time"

// Relay transport and protocol.
const (
	RelayMuxMagic         = "AGBY"
	RelayMuxAcceptBacklog = 256
	RelayMuxKeepAlive     = 30 * time.Second
	RelayMuxWriteTimeout  = 10 * time.Second
	RelayMuxStreamWindow  = 6 << 20
	RelayMuxStreamOpen    = 15 * time.Second
	RelayMuxStreamClose   = 30 * time.Second
	RelayMaxFrameBytes    = 64 << 10
	RelayHeartbeat        = 25 * time.Second
	RelayHandshakeTimeout = 15 * time.Second
	RelayByeTimeout       = time.Second
	RelayBufioBytes       = 4096
	RelayCopyBufferBytes  = 32 << 10
	RelayUDPBufferBytes   = 65535
	RelayUDPReadTimeout   = 5 * time.Second
	RelayAcceptWait       = 10 * time.Second
	RelayReconnectBase    = time.Second
	RelayReconnectMax     = 30 * time.Second
	RelayDefaultPort      = "443"
	RelayHTTPPort         = "80"
	RelayHTTPSPort        = "443"
	RelayBindAny          = "0.0.0.0"
	RelaySessionHistory   = 32
)

// Log field names used by the relay and its diagnostics.
const (
	FieldAgent  = "agent"
	FieldRelay  = "relay"
	FieldReason = "reason"
	FieldPort   = "port"
	FieldAddr   = "addr"
	FieldRemote = "remote"
	FieldExpose = "expose"
	FieldStage  = "stage"
	FieldErr    = "err"
	FieldListen = "listen"
	FieldDomain = "domain"
)

// Relay session event kinds, as recorded in the relay's session history.
const (
	RelayEventOpened     = "opened"
	RelayEventClosed     = "closed"
	RelayEventReplaced   = "replaced"
	RelayEventProxyError = "proxy_error"
)

// RelayAgentNamespace is the logger namespace used by the local agent.
const RelayAgentNamespace = "relay-agent"

// Relay identifiers, storage and network names.
const (
	RelayName            = "relay"
	RelayBucket          = "relay_routes"
	RelayAgentsBucket    = "relay_agents"
	RelayClaimsBucket    = "relay_claims"
	AuthMethodEnrollment = "enrollment"
	AgentStatusActive    = "active"
	AgentStatusRevoked   = "revoked"
)

// Relay message and error strings shared by the protocol and diagnostics.
const (
	ErrRelayURL      = "invalid relay URL"
	ErrRelayAuth     = "authentication failed"
	MsgControlClosed = "relay control connection closed"
	ErrLoadHosts     = "load hosts: "
	ErrLoadConfig    = "load config: "
	SecretScheme     = "ss://"
	StateRunning     = "running"
	StateStopped     = "stopped"
)

// Relay diagnostics.
const (
	RelayCheckAttempts   = 4
	RelayCheckWait       = time.Second
	RelayCheckTimeout    = 5 * time.Second
	RelayCheckMaxWait    = 8 * time.Second
	RelayCheckBodyBytes  = 64 << 10
	RelayAuthTimeout     = 10 * time.Second
	RelayDialTimeout     = 2 * time.Second
	RelayStateTimeout    = 2 * time.Second
	RelayCertWarnBefore  = 14 * 24 * time.Hour
	RelayChurnWindow     = 15 * time.Minute
	RelayFreshSessionAge = 30 * time.Second
)
