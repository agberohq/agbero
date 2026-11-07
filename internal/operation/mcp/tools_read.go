package mcp

import (
	"context"
	"runtime"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ReadDeps supplies the daemon state the read tools expose. The daemon wires
// these closures so the tools never reach into package globals.
type ReadDeps struct {
	Version   string
	Commit    string
	BuildDate string
	StartedAt time.Time

	KeeperLocked   func() bool
	ClusterMembers func() int
	AdminEnabled   bool
}

type StatusOutput struct {
	Version         string `json:"version"`
	Uptime          string `json:"uptime"`
	KeeperLocked    bool   `json:"keeper_locked"`
	ClusterMembers  int    `json:"cluster_members"`
	AdminEnabled    bool   `json:"admin_enabled"`
	ReloadSupported bool   `json:"reload_supported"`
	Mode            string `json:"mode"`
}

type SystemOutput struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// RegisterReadTools registers the read tools named in allowed. Tools that are
// not in the map are not advertised by tools/list.
func RegisterReadTools(server *sdk.Server, deps ReadDeps, allowed map[string]bool) {
	if allowed["status"] {
		sdk.AddTool(server, &sdk.Tool{
			Name:        "agbero_status",
			Description: "Agbero runtime status: version, uptime, keeper lock, cluster size, admin state, mode. Read-only.",
		}, deps.status)
	}
	if allowed["system"] {
		sdk.AddTool(server, &sdk.Tool{
			Name:        "agbero_system_info",
			Description: "Agbero build information: version, commit, build date, Go version, OS, architecture. Read-only.",
		}, deps.system)
	}
}

func (d ReadDeps) status(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, StatusOutput, error) {
	if !readScope(ctx) {
		return nil, StatusOutput{}, ErrInvalidScope
	}
	locked := true
	if d.KeeperLocked != nil {
		locked = d.KeeperLocked()
	}
	members := 0
	if d.ClusterMembers != nil {
		members = d.ClusterMembers()
	}
	return nil, StatusOutput{
		Version:         d.Version,
		Uptime:          time.Since(d.StartedAt).Round(time.Second).String(),
		KeeperLocked:    locked,
		ClusterMembers:  members,
		AdminEnabled:    d.AdminEnabled,
		ReloadSupported: true,
		Mode:            "daemon",
	}, nil
}

func (d ReadDeps) system(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, SystemOutput, error) {
	if !readScope(ctx) {
		return nil, SystemOutput{}, ErrInvalidScope
	}
	return nil, SystemOutput{
		Version:   d.Version,
		Commit:    d.Commit,
		BuildDate: d.BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}, nil
}

func readScope(ctx context.Context) bool {
	return HasScope(ClaimsFromContext(ctx), ScopeRead)
}
