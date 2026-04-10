package helper

import (
	keeperlib "github.com/agberohq/keeper"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

// Helper is the shared dependency container threaded through all CLI commands.
// The Keeper store is opened onFce in main() and injected here; no command
// should open its own store.
type Helper struct {
	Logger   *ll.Logger
	Shutdown *jack.Shutdown
	Cfg      *Config
	Store    *keeperlib.Keeper // single, already-unlocked store for this process
}

// New constructs a Helper.  store may be nil for commands that do not require
// the keeper (e.g. serve, proxy, secret generate).
func New(logger *ll.Logger, shutdown *jack.Shutdown, cfg *Config, store *keeperlib.Keeper) *Helper {
	return &Helper{
		Logger:   logger,
		Shutdown: shutdown,
		Cfg:      cfg,
		Store:    store,
	}
}

func (h *Helper) Config() *Configuration { return &Configuration{p: h} }
func (h *Helper) Secret() *Secret        { return &Secret{p: h} }
func (h *Helper) Keeper() *Keeper        { return &Keeper{p: h} }
func (h *Helper) Host() *Host            { return &Host{p: h} }
func (h *Helper) Cert() *Cert            { return &Cert{p: h} }
func (h *Helper) Cluster() *Cluster      { return &Cluster{p: h} }
func (h *Helper) Home() *Home            { return &Home{p: h} }
func (h *Helper) Ephemeral() *Ephemeral  { return &Ephemeral{p: h} }
func (h *Helper) System() *System        { return &System{p: h} }
func (h *Helper) Admin() *Admin          { return &Admin{p: h} }
func (h *Helper) Run() *Run              { return &Run{p: h} }
func (h *Helper) Service() *Service      { return &Service{p: h} }
