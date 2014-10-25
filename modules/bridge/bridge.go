package bridge

import (
	"sync"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/logs"
)

type Bridge interface {
	RouteToken(token cipherset.Token, to *e3x.Exchange)
	BreakRoute(token cipherset.Token)
}

type module struct {
	mtx         sync.RWMutex
	e           *e3x.Endpoint
	tokenRoutes map[cipherset.Token]*e3x.Exchange
	log         *logs.Logger
}

type moduleKeyType string

const moduleKey = moduleKeyType("bridge")

func Register(e *e3x.Endpoint) {
	e.Use(moduleKey, newBridge(e))
}

func FromEndpoint(e *e3x.Endpoint) Bridge {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}
	return mod.(*module)
}

func newBridge(e *e3x.Endpoint) *module {
	return &module{
		e:           e,
		tokenRoutes: make(map[cipherset.Token]*e3x.Exchange),
		log:         logs.Module("bridge").From(e.LocalHashname()),
	}
}

func (mod *module) Init() error {

	e3x.TransportsFromEndpoint(mod.e).Wrap(func(c transports.Config) transports.Config {
		return transportConfig{mod, c}
	})

	e3x.ObserversFromEndpoint(mod.e).Register(mod.on_exchange_closed)

	return nil
}

func (mod *module) Start() error { return nil }
func (mod *module) Stop() error  { return nil }

func (mod *module) RouteToken(token cipherset.Token, to *e3x.Exchange) {
	mod.mtx.Lock()
	mod.tokenRoutes[token] = to
	mod.mtx.Unlock()
}

func (mod *module) BreakRoute(token cipherset.Token) {
	mod.mtx.Lock()
	delete(mod.tokenRoutes, token)
	mod.mtx.Unlock()
}

func (mod *module) lookupToken(token cipherset.Token) *e3x.Exchange {
	mod.mtx.RLock()
	ex := mod.tokenRoutes[token]
	mod.mtx.RUnlock()
	return ex
}

func (mod *module) on_exchange_closed(e *e3x.ExchangeClosedEvent) {
	mod.mtx.Lock()
	defer mod.mtx.Unlock()

	for token, x := range mod.tokenRoutes {
		if e.Exchange == x {
			delete(mod.tokenRoutes, token)
		}
	}
}

type transportConfig struct {
	mod *module
	c   transports.Config
}

func (c transportConfig) Open() (transports.Transport, error) {
	t, err := c.c.Open()
	if err != nil {
		return nil, err
	}
	return &transport{c.mod, t}, nil
}

type transport struct {
	mod *module
	t   transports.Transport
}

func (t *transport) LocalAddresses() []transports.Addr {
	return t.t.LocalAddresses()
}

func (t *transport) ReadMessage(p []byte) (n int, src transports.Addr, err error) {
	for {
		n, src, err = t.t.ReadMessage(p)
		if err != nil {
			return n, src, err
		}

		buf := p[:n]

		var (
			token = cipherset.ExtractToken(buf)
			ex    = t.mod.lookupToken(token)
		)

		// not a bridged message
		if ex == nil {
			return n, src, err
		}

		// detect message type
		var msgtype = "PKT"
		if buf[0] == 0 && buf[1] == 1 {
			msgtype = "HDR"
		}

		// handle bridged message
		err = t.t.WriteMessage(buf, ex.ActivePath())
		if err != nil {
			// TODO handle error
			t.mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %x %s error=%s\x1B[0m", msgtype, token, ex.ActivePath(), err)
		} else {
			t.mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %x %s\x1B[0m", msgtype, token, ex.ActivePath())
		}

		// continue reading messages
	}

	panic("unreachable")
}

func (t *transport) WriteMessage(p []byte, dst transports.Addr) error {
	return t.t.WriteMessage(p, dst)
}

func (t *transport) Close() error {
	return t.t.Close()
}
