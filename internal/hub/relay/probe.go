package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ProbeAuth validates an agent's enrollment token or credential against a
// running relay without enrolling the agent or issuing a credential.
func ProbeAuth(ctx context.Context, relayURL, agent, enrollToken, credential string, insecure bool) error {
	_, err := ProbeSession(ctx, relayURL, agent, enrollToken, credential, insecure)
	return err
}

// ProbeSession authenticates like ProbeAuth and returns the relay's view of the
// agent's session. The report is nil when the relay predates session reports.
func ProbeSession(ctx context.Context, relayURL, agent, enrollToken, credential string, insecure bool) (*SessionReport, error) {
	u, err := url.Parse(relayURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid relay URL")
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	d := &tls.Dialer{Config: &tls.Config{
		ServerName:         u.Hostname(),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeFrame(conn, hello{
		Kind: frameCheck, Agent: agent, Token: credential, EnrollToken: enrollToken,
	}); err != nil {
		return nil, err
	}
	var a ack
	if err := readFrame(conn, &a); err != nil {
		return nil, err
	}
	if !a.OK {
		if a.Error == "" {
			a.Error = "authentication failed"
		}
		return nil, fmt.Errorf("%s", a.Error)
	}
	return a.Session, nil
}
