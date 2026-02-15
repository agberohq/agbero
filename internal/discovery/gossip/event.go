package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/retry"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/memberlist"
)

type event struct {
	s *Service
}

func (e *event) NotifyJoin(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	go func(n *memberlist.Node) {
		e.processNode(n)
		e.s.logger.Fields("node", n.Name).Info("node joined")
	}(node)
}

func (e *event) NotifyLeave(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	e.s.hm.RemoveGossipNode(node.Name)
	e.s.logger.Fields("node", node.Name).Info("node left and unregistered")
}

func (e *event) NotifyUpdate(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	// Run asynchronously
	go e.processNode(node)
}

func (e *event) fetchToken(node *memberlist.Node, meta *Meta) (string, error) {
	authPath := meta.AuthPath
	if authPath == "" {
		authPath = woos.DefaultAuthPath
	}

	url := fmt.Sprintf(woos.URLFormat, node.Addr.String(), meta.Port, authPath)
	var token string

	// Use standard retry logic with exponential backoff
	// Context timeout covers the *entire* retry sequence duration
	ctx, cancel := context.WithTimeout(context.Background(), e.s.authTimeout)
	defer cancel()

	err := retry.DoCtx(ctx, func() error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

		// NOTE: http.DefaultClient has no timeout, but the ctx above handles it
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err // Will retry on network error
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// Don't retry on 4xx errors (client error), only 5xx
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return backoff.Permanent(fmt.Errorf("%w: status = (%d)", woos.ErrAuthEndpoint, resp.StatusCode))
			}
			return fmt.Errorf("auth endpoint status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return backoff.Permanent(err) // Don't retry invalid JSON
		}
		if out.Token == "" {
			return backoff.Permanent(woos.ErrEmptyToken)
		}
		token = out.Token
		return nil
	})

	return token, err
}

func (e *event) processNode(node *memberlist.Node) {
	if len(node.Meta) == 0 {
		return
	}

	var meta Meta
	if err := json.Unmarshal(node.Meta, &meta); err != nil {
		e.s.logger.Fields("node", node.Name, "err", err).Warn("gossip invalid metadata")
		return
	}

	if meta.Host == "" || meta.Port <= 0 {
		return
	}

	if meta.Path == "" {
		meta.Path = woos.Slash
	}
	if !strings.HasPrefix(meta.Path, woos.Slash) {
		meta.Path = woos.Slash + meta.Path
	}

	if e.s.tokenManager != nil {
		if meta.Token == "" {
			tok, err := e.fetchToken(node, &meta)
			if err != nil {
				e.s.logger.Fields("node", node.Name, "err", err).
					Warn("gossip rejected: auth fetch failed")
				return
			}
			meta.Token = tok
		}

		svcName, err := e.s.tokenManager.Verify(meta.Token)
		if err != nil {
			e.s.logger.Fields("node", node.Name, "err", err).
				Warn("gossip rejected: invalid token")
			return
		}

		if svcName != meta.Host && !strings.HasSuffix(meta.Host, "."+svcName) {
			e.s.logger.Fields("node", node.Name, "token_sub", svcName, "host", meta.Host).
				Warn("gossip rejected: token subject does not authorize this host")
			return
		}

		e.s.logger.Fields("node", node.Name, "svc", svcName).Debug("gossip authorized")
	}

	weight := meta.Weight
	if weight <= 0 {
		weight = 1
	}

	healthPath := meta.HealthPath
	if healthPath == "" {
		healthPath = woos.Slash
	}
	if !strings.HasPrefix(healthPath, woos.Slash) {
		healthPath = woos.Slash + healthPath
	}

	target := fmt.Sprintf(woos.URLPrefixFormat, node.Addr.String(), meta.Port)

	route := alaye.Route{
		Path: meta.Path,
		Backends: alaye.Backend{
			Enabled:  alaye.Active,
			Strategy: alaye.StrategyRoundRobin,
			Servers: []alaye.Server{
				{
					Address: target,
					Weight:  weight,
				},
			},
		},
		HealthCheck: alaye.HealthCheck{
			Enabled: alaye.Active,
			Path:    healthPath,
		},
	}

	if meta.StripPrefix {
		route.StripPrefixes = []string{meta.Path}
	}

	e.s.hm.UpdateGossipNode(node.Name, meta.Host, route)

	e.s.logger.Fields(
		"node", node.Name,
		"host", meta.Host,
		"path", meta.Path,
		"target", target,
		"weight", weight,
	).Info("gossip route upserted")
}
