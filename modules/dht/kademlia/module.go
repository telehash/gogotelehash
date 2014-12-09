package kademlia

import (
	"sync"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/modules/peers"
)

type moduleKeyType string

const moduleKey = moduleKeyType("dht/kademlia")

var (
	_ e3x.Module = (*module)(nil)
)

type module struct {
	mtx      sync.Mutex
	table    table
	e        *e3x.Endpoint
	mesh     mesh.Mesh
	peers    peers.Peers
	seekFunc func(target string, peer *e3x.Exchange) ([]hashname.H, error)
}

type DHT interface {
}

func Module() func(*e3x.Endpoint) error {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, &module{e: e})(e)
	}
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
	return nil
}

func (mod *module) Start() error { return nil }
func (mod *module) Stop() error  { return nil }

func (mod *module) connectToCandidate(c *candidatePeer) (next bool) {
	var (
		ex  *e3x.Exchange
		err error
	)

	if c == nil {
		return false
	}

	for _, router := range c.routers {
		routerEx, err := mod.e.Dial(e3x.HashnameIdentifier(router))
		if err != nil {
			continue
		}

		ex, err = mod.peers.IntroduceVia(c.hashname, routerEx.RemoteIdentity())
		if err != nil {
			continue
		}

		break
	}

	if ex == nil {
		mod.mtx.Lock()
		mod.table.deactivatePeer(c.hashname)
		mod.mtx.Unlock()
		return true
	}

	tag, err := mod.mesh.Link(ex.RemoteIdentity(), nil)
	if err != nil {
		mod.mtx.Lock()
		mod.table.deactivatePeer(c.hashname)
		mod.mtx.Unlock()
		return true
	}

	mod.mtx.Lock()
	mod.table.activatePeer(c.hashname, tag)
	mod.mtx.Unlock()
	return true
}

func (mod *module) connectToCandidates() {
	var wg = &sync.WaitGroup{}

	for {
		mod.mtx.Lock()
		c := mod.table.nextCandidate()
		mod.mtx.Unlock()
		if c == nil {
			break
		}

		wg.Add(1)
		go func(c *candidatePeer) {
			defer wg.Done()
			mod.connectToCandidate(c)
		}(c)
	}

	wg.Wait()
}
