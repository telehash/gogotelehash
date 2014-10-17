package bridge

import (
	"sync"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

type Bridge interface {
	RouteToken(token cipherset.Token, to *e3x.Exchange)
	BreakRoute(token cipherset.Token)
}

type module struct {
	mtx         sync.RWMutex
	e           *e3x.Endpoint
	tokenRoutes map[cipherset.Token]*e3x.Exchange
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
	}
}

func (mod *module) Init() error {
	e3x.TransportsFromEndpoint(mod.e).Wrap(func(c transports.Config) transports.Config {
		return transportConfig{mod, c}
	})
	return nil
}

func (mod *module) Start() error {
	return nil
}

func (mod *module) Stop() error {
	return nil
}

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

func (t *transport) Run(w <-chan transports.WriteOp, r chan<- transports.ReadOp, e chan<- events.E) <-chan struct{} {
	w2 := make(chan transports.WriteOp)
	r2 := make(chan transports.ReadOp)
	go t.run_bridge(w2, r2, w, r)
	return t.t.Run(w2, r2, e)
}

func (t *transport) run_bridge(
	w2 chan transports.WriteOp, r2 chan transports.ReadOp,
	w <-chan transports.WriteOp, r chan<- transports.ReadOp,
) {
LOOP:
	for {
		select {

		case op, open := <-w:
			if !open {
				close(w2)
				return
			}
			w2 <- op

		case op, open := <-r2:
			if !open {
				return
			}

			token := cipherset.ExtractToken(op.Msg)
			ex := t.mod.lookupToken(token)
			if ex == nil {
				r <- op
				continue LOOP
			}

			writeOp := transports.WriteOp{
				C:   make(chan error, 1),
				Dst: ex.ActivePath(),
				Msg: op.Msg,
			}
			if writeOp.Dst == nil {
				continue LOOP
			}

			w2 <- writeOp

		}
	}
}
