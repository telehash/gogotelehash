package peers

import (
	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
)

type Config struct {
	DisableRouter bool
	AllowPeer     func(from, to hashname.H) bool
	AllowConnect  func(from, via hashname.H) bool
}

type Peers interface {
	IntroduceVia(dst hashname.H, router *e3x.Identity) (*e3x.Exchange, error)
	// DialVia(dst, router *e3x.Identity) (*e3x.Exchange, error)
}

type module struct {
	e      *e3x.Endpoint
	m      mesh.Mesh
	config Config
}

type moduleKeyType string

const moduleKey = moduleKeyType("peers")

func Register(e *e3x.Endpoint, cnf Config) {
	e.Use(moduleKey, newPeers(e, cnf))
}

func FromEndpoint(e *e3x.Endpoint) Peers {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}

	return mod.(*module)
}

func newPeers(e *e3x.Endpoint, cnf Config) *module {
	return &module{
		e:      e,
		config: cnf,
	}
}

func (mod *module) Init() error {
	mod.m = mesh.FromEndpoint(mod.e)
	if mod.m == nil {
		panic("the peers module requires the mesh module")
	}

	mod.e.AddHandler("peer", e3x.HandlerFunc(mod.handle_peer))
	mod.e.AddHandler("connect", e3x.HandlerFunc(mod.handle_connect))
	return nil
}

func (mod *module) Start() error {
	return nil
}

func (mod *module) Stop() error {
	return nil
}

func (mod *module) IntroduceVia(dst hashname.H, via *e3x.Identity) (*e3x.Exchange, error) {
	router, err := mod.e.Dial(via)
	if err != nil {
		return nil, err
	}

	err = mod.introduceVia(router, dst)
	if err != nil {
		return nil, err
	}

	return nil, nil
}
