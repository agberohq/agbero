// Package xserverless provides handlers for executing functions as web services.
// It includes REST proxying and direct binary execution for ephemeral workloads.
package xserverless

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
)

const (
	defaultRESTTimeout = 30 * time.Second
)

type RestConfig struct {
	Resource  *resource.Resource
	REST      alaye.REST
	GlobalEnv map[string]alaye.Value
	RouteEnv  map[string]alaye.Value
}

type RestHandler struct {
	res       *resource.Resource
	cfg       alaye.REST
	globalEnv map[string]alaye.Value
	routeEnv  map[string]alaye.Value
	client    *http.Client
}

// NewRest initializes a REST serverless handler with the provided configuration.
// It prepares an HTTP client with the specified timeout for upstream communication.
func NewRest(cfg RestConfig) *RestHandler {
	timeout := cfg.REST.Timeout.StdDuration()
	if timeout <= 0 {
		timeout = defaultRESTTimeout
	}

	return &RestHandler{
		res:       cfg.Resource,
		cfg:       cfg.REST,
		globalEnv: cfg.GlobalEnv,
		routeEnv:  cfg.RouteEnv,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// ServeHTTP proxies incoming requests to the configured serverless REST endpoint.
// It handles URL query parameter forwarding and custom header injection.
func (h *RestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL, err := url.Parse(h.cfg.URL)
	if err != nil {
		h.res.Logger.Fields("url", h.cfg.URL, "err", err).Error("serverless: invalid rest url")
		http.Error(w, "Invalid Target URL", http.StatusInternalServerError)
		return
	}

	h.prepareURL(targetURL, r.URL.Query())

	proxyReq, err := http.NewRequestWithContext(r.Context(), h.cfg.Method, targetURL.String(), r.Body)
	if err != nil {
		h.res.Logger.Fields("err", err).Error("serverless: failed to create rest request")
		http.Error(w, "Request Initialization Failed", http.StatusInternalServerError)
		return
	}

	h.prepareHeaders(proxyReq.Header)

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		h.res.Logger.Fields("url", targetURL.String(), "err", err).Error("serverless: upstream call failed")
		http.Error(w, "Upstream Service Unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.res.Logger.Fields("err", err).Debug("serverless: rest stream interrupted")
	}
}

// prepareURL merges incoming query parameters with static parameters defined in config.
// It uses the local resolver to interpolate environment variables in query values.
func (h *RestHandler) prepareURL(u *url.URL, incoming url.Values) {
	query := u.Query()

	if h.cfg.ForwardQuery {
		for k, vv := range incoming {
			for _, v := range vv {
				query.Add(k, v)
			}
		}
	}

	resolver := h.getResolver()
	for k, v := range h.cfg.Query {
		query.Set(k, v.Resolve(resolver))
	}

	u.RawQuery = query.Encode()
}

// prepareHeaders injects the static headers defined in the REST configuration.
// These headers override any incoming request headers with the same name.
func (h *RestHandler) prepareHeaders(hdt http.Header) {
	for k, v := range h.cfg.Headers {
		hdt.Set(k, v)
	}
}

// getResolver creates a closure that resolves environment variable keys from merged contexts.
// It prioritizes REST-specific env, then route-level, then global server env.
func (h *RestHandler) getResolver() func(string) string {
	merged := make(map[string]string)

	for k, v := range h.globalEnv {
		merged[k] = v.String()
	}
	for k, v := range h.routeEnv {
		merged[k] = v.String()
	}
	for k, v := range h.cfg.Env {
		merged[k] = v.String()
	}

	return func(key string) string {
		return merged[key]
	}
}
