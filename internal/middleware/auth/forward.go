package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	cache2 "git.imaxinacion.net/aibox/agbero/internal/pkg/cache"
	"github.com/olekukonko/errors"
)

var authCaches = make(map[string]*cache2.Cache)
var cacheMu sync.RWMutex

func getCache(name string) *cache2.Cache {
	cacheMu.RLock()
	if c, ok := authCaches[name]; ok {
		cacheMu.RUnlock()
		return c
	}
	cacheMu.RUnlock()

	cacheMu.Lock()
	defer cacheMu.Unlock()

	if c, ok := authCaches[name]; ok {
		return c
	}

	c := cache2.New(cache2.Options{
		MaximumSize: 10000,
		OnDelete:    cache2.CloserDelete,
	})
	authCaches[name] = c
	return c
}

var defaultHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	},
}

func Forward(cfg *alaye.ForwardAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	if cfg.URL == "" {
		return func(next http.Handler) http.Handler { return next }
	}

	onFailure := strings.ToLower(cfg.OnFailure)
	if onFailure != woos.Allow {
		onFailure = woos.Deny
	}

	cacheName := cfg.Name
	if cacheName == "" {
		cacheName = "default_" + cfg.URL
	}
	authCache := getCache(cacheName)

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var client *http.Client
	if cfg.TLS != nil && cfg.TLS.Enabled.Active() {
		tlsConfig, err := createTLSConfig(cfg.TLS)
		if err != nil {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Forward Auth TLS Error: "+err.Error(), http.StatusInternalServerError)
				})
			}
		}
		client = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				TLSClientConfig:     tlsConfig,
			},
		}
	} else {
		client = defaultHTTPClient
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cacheKey := buildCacheKey(r, cfg.Request.CacheKey, cfg.Name)

			if cached, ok := authCache.Load(cacheKey); ok {
				if allowed, ok := cache2.Get[bool](cached); ok && allowed {
					if cfg.Response.Enabled.Active() {
						if headersItem, ok := authCache.Load(cacheKey + "_headers"); ok {
							if headers, ok := cache2.Get[http.Header](headersItem); ok {
								copyHeadersToRequest(headers, r, cfg.Response.CopyHeaders)
							}
						}
					}
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Forbidden (Cached)", http.StatusForbidden)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			method := http.MethodGet
			if cfg.Request.Method != "" {
				method = strings.ToUpper(cfg.Request.Method)
			}

			authReq, err := http.NewRequestWithContext(ctx, method, cfg.URL, nil)
			if err != nil {
				handleFailure(w, r, onFailure, next, "failed to create auth request")
				return
			}

			if cfg.Request.Enabled.Active() {
				copyHeaders(r.Header, authReq.Header, cfg.Request.Headers)
			} else {
				copyHeaders(r.Header, authReq.Header, nil)
			}

			if cfg.Request.Enabled.Active() {
				if cfg.Request.ForwardMethod {
					authReq.Header.Set(woos.HeaderXOriginalMethod, r.Method)
				}
				if cfg.Request.ForwardURI {
					authReq.Header.Set(woos.HeaderXOriginalURI, r.URL.RequestURI())
				}
				if cfg.Request.ForwardIP {
					authReq.Header.Set(woos.HeaderXForwardedFor, clientip.ClientIP(r))
				}
			}

			if cfg.Request.Enabled.Active() {
				switch cfg.Request.BodyMode {
				case "metadata":
					authReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))
					contentLength := r.Header.Get("Content-Length")
					if contentLength == "" && r.ContentLength > 0 {
						contentLength = strconv.FormatInt(r.ContentLength, 10)
					}
					if contentLength != "" {
						authReq.Header.Set("Content-Length", contentLength)
					}
				case "limited":
					maxBody := cfg.Request.MaxBody
					if maxBody <= 0 {
						maxBody = 64 * 1024
					}
					body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
					if err != nil {
						handleFailure(w, r, onFailure, next, "failed to read body")
						return
					}
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
					authReq.Body = io.NopCloser(bytes.NewReader(body))
					authReq.ContentLength = int64(len(body))
				}
			}

			resp, err := client.Do(authReq)
			if err != nil {
				handleFailure(w, r, onFailure, next, "auth service unavailable")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				if cfg.Response.Enabled.Active() {
					headersToCopy := make(http.Header)
					for _, h := range cfg.Response.CopyHeaders {
						if v := resp.Header.Get(h); v != "" {
							headersToCopy.Set(h, v)
							r.Header.Set(h, v)
						}
					}

					if cfg.Response.CacheTTL > 0 {
						allowItem := &cache2.Item{Value: true}
						headersItem := &cache2.Item{Value: headersToCopy}
						authCache.StoreTTL(cacheKey, allowItem, cfg.Response.CacheTTL)
						authCache.StoreTTL(cacheKey+"_headers", headersItem, cfg.Response.CacheTTL)
					}
				} else if cfg.Response.CacheTTL > 0 {
					allowItem := &cache2.Item{Value: true}
					authCache.StoreTTL(cacheKey, allowItem, cfg.Response.CacheTTL)
				}

				next.ServeHTTP(w, r)
				return
			}

			denyItem := &cache2.Item{Value: false}
			authCache.StoreTTL(cacheKey, denyItem, 10*time.Second)

			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		})
	}
}

func createTLSConfig(cfg *alaye.ForwardTLS) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair(
			[]byte(cfg.ClientCert.String()),
			[]byte(cfg.ClientKey.String()),
		)
		if err != nil {
			return nil, errors.Newf("failed to parse client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.CA != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(cfg.CA.String())) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

func buildCacheKey(r *http.Request, cacheKeyHeaders []string, prefix string) string {
	h := sha256.New()
	if prefix != "" {
		h.Write([]byte(prefix))
		h.Write([]byte("|"))
	}
	if len(cacheKeyHeaders) == 0 {
		cacheKeyHeaders = []string{"Authorization"}
	}
	for _, header := range cacheKeyHeaders {
		h.Write([]byte(r.Header.Get(header)))
		h.Write([]byte("|"))
	}
	h.Write([]byte(r.Method))
	h.Write([]byte("|"))
	h.Write([]byte(r.URL.Path))
	return hex.EncodeToString(h.Sum(nil))
}

func copyHeaders(src http.Header, dst http.Header, keys []string) {
	if len(keys) == 0 {
		for _, key := range []string{"Authorization", "Cookie"} {
			if v := src.Get(key); v != "" {
				dst.Set(key, v)
			}
		}
		return
	}

	for _, k := range keys {
		if v := src.Get(k); v != "" {
			dst.Set(k, v)
		}
	}
}

func copyHeadersToRequest(src http.Header, r *http.Request, keys []string) {
	for _, k := range keys {
		if v := src.Get(k); v != "" {
			r.Header.Set(k, v)
		}
	}
}

func handleFailure(w http.ResponseWriter, r *http.Request, onFailure string, next http.Handler, msg string) {
	if onFailure == woos.Allow {
		next.ServeHTTP(w, r)
		return
	}
	http.Error(w, msg, http.StatusForbidden)
}
