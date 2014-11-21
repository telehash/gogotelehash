package kademlia

import (
	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/modules/peers"
)

type moduleKeyType string

const moduleKey = moduleKeyType("dht/kademlia")

var (
	_ e3x.Module = (*module)(nil)
)

type module struct {
	table table
	e     *e3x.Endpoint
	mesh  mesh.Mesh
	peers peers.Peers
}

type DHT interface {
}

func Register(e *e3x.Endpoint) {
	e.Use(moduleKey, &module{e: e})
}

func FromEndpoint(e *e3x.Endpoint) DHT {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}

	return mod.(*module)
}

func (mod *module) Init() error {
	mod.mesh = mesh.FromEndpoint(mod.e)
	mod.peers = peers.FromEndpoint(mod.e)
	mod.table.init()
}

func (mod *module) connectToCandidate() {
	c := mod.table.nextCandidate()
	if c == nil {
		return
	}

	for _, router := range c.routers {
		routerEx, err := mod.e.Dial(router)
		if err != nil {
			continue
		}

		ex, err := mod.peers.IntroduceVia(c.hashname, routerEx)
		if err != nil {
			continue
		}

		break
	}
}
