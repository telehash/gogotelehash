package peers

import (
	"io"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/modules/mesh"
	"github.com/telehash/gogotelehash/transports"
)

type Config struct {
	DisableRouter bool
	AllowPeer     func(from, to hashname.H) bool
	AllowConnect  func(from, via hashname.H) bool
}

type Peers interface {
	IntroduceVia(dst hashname.H, router *e3x.Identity) (*e3x.Exchange, error)
}

type module struct {
	e      *e3x.Endpoint
	m      mesh.Mesh
	config Config

	mtx             sync.Mutex
	peerListener    *e3x.Listener
	connectListener *e3x.Listener
	pending         map[hashname.H]*pendingIntroduction
}

type pendingIntroduction struct {
	mtx          sync.Mutex
	cnd          *sync.Cond
	mod          *module
	hashname     hashname.H
	done         bool
	x            *e3x.Exchange
	err          error
	timeoutTimer *time.Timer
}

type moduleKeyType string

const moduleKey = moduleKeyType("peers")

func Module(cnf Config) e3x.EndpointOption {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, newPeers(e, cnf))(e)
	}
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
		e:       e,
		config:  cnf,
		pending: make(map[hashname.H]*pendingIntroduction),
	}
}

func (mod *module) Init() error {
	e3x.TransportsFromEndpoint(mod.e).Wrap(func(conf transports.Config) transports.Config {
		return &transportConfig{conf, mod}
	})

	mod.m = mesh.FromEndpoint(mod.e)
	if mod.m == nil {
		panic("the peers module requires the mesh module")
	}

	return nil
}

func (mod *module) Start() error {
	mod.peerListener = mod.e.Listen("peer", false)
	mod.connectListener = mod.e.Listen("connect", false)

	go mod.acceptPeerChannels()
	go mod.acceptConnectChannels()

	return nil
}

func (mod *module) Stop() error {
	mod.peerListener.Close()
	mod.connectListener.Close()

	return nil
}

func (mod *module) IntroduceVia(dst hashname.H, via *e3x.Identity) (*e3x.Exchange, error) {
	i, dial := mod.registerIntroduction(dst)

	if dial {
		router, err := mod.e.Dial(via)
		if err != nil {
			return nil, err
		}

		err = mod.introduceVia(router, dst)
		if err != nil {
			return nil, err
		}
	}

	return i.wait()
}

func (mod *module) registerIntroduction(dst hashname.H) (i *pendingIntroduction, dial bool) {
	mod.mtx.Lock()
	i = mod.pending[dst]
	if i == nil {
		dial = true
		i = newPendingIntroduction(mod, dst, 2*time.Minute)
		mod.pending[dst] = i
	}
	mod.mtx.Unlock()

	return i, dial
}

func (mod *module) getIntroduction(dst hashname.H) *pendingIntroduction {
	mod.mtx.Lock()
	i := mod.pending[dst]
	mod.mtx.Unlock()

	return i
}

func newPendingIntroduction(mod *module, hn hashname.H, timeout time.Duration) *pendingIntroduction {
	i := &pendingIntroduction{mod: mod, hashname: hn}
	i.cnd = sync.NewCond(&i.mtx)
	i.timeoutTimer = time.AfterFunc(timeout, i.timeout)
	return i
}

func (i *pendingIntroduction) wait() (*e3x.Exchange, error) {
	i.mtx.Lock()

	for !i.done {
		i.cnd.Wait()
	}

	i.cnd.Signal()
	i.mtx.Unlock()

	return i.x, i.err
}

func (i *pendingIntroduction) timeout() {
	i.resolve(nil, e3x.ErrTimeout)
}

func (i *pendingIntroduction) resolve(x *e3x.Exchange, err error) {
	if i == nil {
		return
	}

	i.mod.mtx.Lock()
	i.mtx.Lock()

	delete(i.mod.pending, i.hashname)

	if !i.done {
		if i.timeoutTimer != nil {
			i.timeoutTimer.Stop()
			i.timeoutTimer = nil
		}

		i.x, i.err = x, err
		i.done = true

		i.cnd.Signal()
	}

	i.mtx.Unlock()
	i.mod.mtx.Unlock()
}

func (mod *module) acceptPeerChannels() {
	for {
		c, err := mod.peerListener.AcceptChannel()
		if err == io.EOF {
			return
		}
		if err != nil {
			continue
		}
		go mod.handle_peer(c)
	}
}

func (mod *module) acceptConnectChannels() {
	for {
		c, err := mod.connectListener.AcceptChannel()
		if err == io.EOF {
			return
		}
		if err != nil {
			continue
		}
		go mod.handle_connect(c)
	}
}
