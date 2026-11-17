package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterResources registers the read-only resources allowed by the config.
func RegisterResources(server *sdk.Server, deps ReadDeps, allowed map[string]bool) {
	if allowed["status"] {
		server.AddResource(&sdk.Resource{
			URI: "agbero://status", Name: "agbero-status",
			Description: "Runtime status", MIMEType: "application/json",
		}, deps.resourceStatus)
	}
	if allowed["config.global"] {
		server.AddResource(&sdk.Resource{
			URI: "agbero://config/global", Name: "agbero-config-global",
			Description: "Redacted global configuration", MIMEType: "application/json",
		}, deps.resourceGlobal)
	}
	if allowed["config.hosts"] {
		server.AddResource(&sdk.Resource{
			URI: "agbero://config/hosts", Name: "agbero-config-hosts",
			Description: "Canonical host summaries", MIMEType: "application/json",
		}, deps.resourceHosts)
	}
	if allowed["config.host"] {
		server.AddResourceTemplate(&sdk.ResourceTemplate{
			URITemplate: "agbero://config/hosts/{domain}", Name: "agbero-config-host",
			Description: "One redacted host configuration", MIMEType: "application/json",
		}, deps.resourceHost)
	}
	if allowed["config.explain"] {
		server.AddResource(&sdk.Resource{
			URI: "agbero://schema", Name: "agbero-schema",
			Description: "Field catalog subset", MIMEType: "application/json",
		}, deps.resourceSchema)
	}
	if allowed["certs.list"] {
		server.AddResource(&sdk.Resource{
			URI: "agbero://certs", Name: "agbero-certs",
			Description: "Certificate inventory (no private keys)", MIMEType: "application/json",
		}, deps.resourceCerts)
	}
}

func (d ReadDeps) resourceStatus(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	_, out, err := d.status(ctx, nil, EmptyInput{})
	if err != nil {
		return nil, err
	}
	return resourceJSON(req.Params.URI, out), nil
}

func (d ReadDeps) resourceGlobal(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	_, out, err := d.getGlobal(ctx, nil, EmptyInput{})
	if err != nil {
		return nil, err
	}
	return resourceJSON(req.Params.URI, out), nil
}

func (d ReadDeps) resourceHosts(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	_, out, err := d.listHosts(ctx, nil, EmptyInput{})
	if err != nil {
		return nil, err
	}
	return resourceJSON(req.Params.URI, out), nil
}

func resourceJSON(uri string, v any) *sdk.ReadResourceResult {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"encode failed"}`)
	}
	return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{
		URI: uri, MIMEType: "application/json", Text: string(b),
	}}}
}

func (d ReadDeps) resourceHost(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	domain, err := url.PathUnescape(strings.TrimPrefix(req.Params.URI, "agbero://config/hosts/"))
	if err != nil {
		return nil, err
	}
	_, out, err := d.getHost(ctx, nil, HostInput{Domain: domain})
	if err != nil {
		return nil, err
	}
	return resourceJSON(req.Params.URI, out), nil
}

func (d ReadDeps) resourceSchema(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	return resourceJSON(req.Params.URI, fieldCatalog), nil
}

func (d ReadDeps) resourceCerts(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
	if !d.authorized(ctx) {
		return nil, ErrInvalidScope
	}
	if d.Certs == nil {
		return nil, ErrAdminPlane
	}
	out, err := d.Certs(ctx)
	if err != nil {
		return nil, err
	}
	return resourceJSON(req.Params.URI, out), nil
}
