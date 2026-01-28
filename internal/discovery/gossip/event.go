package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/hashicorp/memberlist"
)

type event struct {
	s *Service
}

func (e *event) NotifyJoin(node *memberlist.Node) {
	if node.Name == e.s.localName {
		return
	}
	e.processNode(node)
	e.s.logger.Fields("node", node.Name).Info("node joined")
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
	e.processNode(node)
}

func (e *event) fetchToken(node *memberlist.Node, meta *Meta) (string, error) {
	authPath := meta.AuthPath
	if authPath == "" {
		authPath = "/.well-known/agbero"
	}

	url := fmt.Sprintf("http://%s:%d%s", node.Addr.String(), meta.Port, authPath)

	ctx, cancel := context.WithTimeout(context.Background(), e.s.authTimeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth endpoint status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token from auth endpoint")
	}
	return out.Token, nil
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
		meta.Path = "/"
	}
	if !strings.HasPrefix(meta.Path, "/") {
		meta.Path = "/" + meta.Path
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
		e.s.logger.Fields("node", node.Name, "svc", svcName).Debug("gossip authorized")
	}

	weight := meta.Weight
	if weight <= 0 {
		weight = 1
	}

	healthPath := meta.HealthPath
	if healthPath == "" {
		healthPath = "/"
	}
	if !strings.HasPrefix(healthPath, "/") {
		healthPath = "/" + healthPath
	}

	target := fmt.Sprintf("http://%s:%d", node.Addr.String(), meta.Port)

	route := alaye.Route{
		Path: meta.Path,
		Backends: alaye.Backend{
			LBStrategy: alaye.StrategyRoundRobin,
			Servers: []alaye.Server{
				{
					Address: target,
					Weight:  weight,
				},
			},
		},
		HealthCheck: &alaye.HealthCheck{
			Path: healthPath,
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
