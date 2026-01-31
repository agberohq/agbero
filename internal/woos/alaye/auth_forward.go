package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type ForwardAuth struct {
	URL string `hcl:"url"` // e.g. "http://auth-service:8080/verify"

	// Headers to copy FROM client request TO auth service (e.g. "Authorization", "Cookie")
	RequestHeaders []string `hcl:"request_headers,optional"`

	// Headers to copy FROM auth response TO backend request (e.g. "X-User-ID")
	AuthResponseHeaders []string `hcl:"auth_response_headers,optional"`

	// On auth server failure (e.g., timeout): "deny" (default) or "allow"
	OnFailure string `hcl:"on_failure,optional"`
}

func (f *ForwardAuth) Validate() error {
	// URL validation
	if f.URL == "" {
		return ErrForwardAuthURLRequired
	}
	if !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
		return ErrForwardAuthURLInvalid
	}

	// Request headers validation (if provided)
	for i, header := range f.RequestHeaders {
		if header == "" {
			return errors.Newf("request_headers[%d]: %w", i, ErrCannotBeEmpty)
		}
	}

	// Auth response headers validation (if provided)
	for i, header := range f.AuthResponseHeaders {
		if header == "" {
			return errors.Newf("auth_response_headers[%d]: %w", i, ErrCannotBeEmpty)
		}
	}

	// OnFailure validation (if provided)
	if f.OnFailure != "" {
		f.OnFailure = strings.ToLower(f.OnFailure)
		if f.OnFailure != "allow" && f.OnFailure != "deny" {
			return ErrForwardAuthOnFailureInvalid
		}
	} else {
		f.OnFailure = DefaultForwardAuthOnFailure // Default
	}

	return nil
}
