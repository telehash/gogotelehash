package peers

import (
	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/modules/mesh"
)

type Config struct {
	DisableRouter bool
	AllowPeer     func(from, to hashname.H) bool
	AllowConnect  func(from, via hashname.H) bool
}

type Peers interface {
}

type peers struct {
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

	return mod.(*peers)
}

func newPeers(e *e3x.Endpoint, cnf Config) *peers {
	return &peers{
		e:      e,
		config: cnf,
	}
}

func (p *peers) Init() error {
	p.m = mesh.FromEndpoint(p.e)
	if p.m == nil {
		panic("the peers module requires the mesh module")
	}

	p.e.AddHandler("peer", e3x.HandlerFunc(p.handle_peer))
	p.e.AddHandler("connect", e3x.HandlerFunc(p.handle_connect))
	return nil
}

func (p *peers) Start() error {
	return nil
}

func (p *peers) Stop() error {
	return nil
}
