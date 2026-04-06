package helper

import (
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/setup"
	keeperlib "github.com/agberohq/keeper"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

type Helper struct {
	Logger   *ll.Logger
	Shutdown *jack.Shutdown
	Cfg      *Config
}

func New(logger *ll.Logger, shutdown *jack.Shutdown, cfg *Config) *Helper {
	return &Helper{
		Logger:   logger,
		Shutdown: shutdown,
		Cfg:      cfg,
	}
}

// openStore opens an unlocked keeper.Keeper.
//
// Resolution order (same as service.go::preflightCheck):
// cfg.Passphrase in agbero.hcl (any expect.Value — env., vault://, b64. …)
// AGBERO_PASSPHRASE environment variable
// Interactive prompt — used in run mode; never in service mode.
func (h *Helper) openStore(configPath string) *keeperlib.Keeper {
	global, err := loadGlobal(configPath)
	if err != nil {
		h.Logger.Fatal("failed to load config: ", err)
	}

	dataDir := global.Storage.DataDir
	if dataDir == "" {
		ctx := setup.NewContext(h.Logger)
		dataDir = ctx.Paths.DataDir
	}
	store, openErr := secrets.Open(secrets.Config{
		DataDir:     dataDir,
		Setting:     &global.Security.Keeper,
		Logger:      h.Logger,
		Interactive: true,
	})
	if openErr != nil {
		h.Logger.Fatal("failed to open keeper: ", openErr)
	}
	return store
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
