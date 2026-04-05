package helper

import (
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

func (h *Helper) Config() *Configuration { return &Configuration{p: h} }
func (h *Helper) Secret() *Secret        { return &Secret{p: h} }
func (h *Helper) Keeper() *Keeper        { return &Keeper{p: h} }
func (h *Helper) Host() *Host            { return &Host{p: h} }
func (h *Helper) Cert() *Cert            { return &Cert{p: h} }
func (h *Helper) Service() *Service      { return &Service{p: h} }
func (h *Helper) Cluster() *Cluster      { return &Cluster{p: h} }
func (h *Helper) Home() *Home            { return &Home{p: h} }
func (h *Helper) Ephemeral() *Ephemeral  { return &Ephemeral{p: h} }
func (h *Helper) System() *System        { return &System{p: h} }
func (h *Helper) Admin() *Admin          { return &Admin{p: h} }
