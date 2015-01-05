package bridge

import (
	"sync"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/util/logs"
)

type Bridge interface {
	RouteToken(token cipherset.Token, source, target *e3x.Exchange)
	BreakRoute(token cipherset.Token)
}

type module struct {
	mtx             sync.RWMutex
	e               *e3x.Endpoint
	packetRoutes    map[cipherset.Token]*e3x.Exchange
	handshakeRoutes map[cipherset.Token]*e3x.Exchange
	log             *logs.Logger
}

type moduleKeyType string

const moduleKey = moduleKeyType("bridge")

func Module() e3x.EndpointOption {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, newBridge(e))(e)
	}
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
		e:               e,
		packetRoutes:    make(map[cipherset.Token]*e3x.Exchange),
		handshakeRoutes: make(map[cipherset.Token]*e3x.Exchange),
	}
}

func (mod *module) Init() error {
	mod.log = logs.Module("bridge").From(mod.e.LocalHashname())

	mod.e.DefaultExchangeHooks().Register(e3x.ExchangeHook{
		OnClosed:     mod.on_exchange_closed,
		OnDropPacket: mod.on_dropped_packet,
	})

	return nil
}

func (mod *module) Start() error { return nil }
func (mod *module) Stop() error  { return nil }

func (mod *module) RouteToken(token cipherset.Token, source, target *e3x.Exchange) {
	mod.mtx.Lock()
	mod.packetRoutes[token] = source
	if target != nil {
		mod.handshakeRoutes[token] = target
	}
	mod.mtx.Unlock()
}

func (mod *module) BreakRoute(token cipherset.Token) {
	mod.mtx.Lock()
	delete(mod.packetRoutes, token)
	delete(mod.handshakeRoutes, token)
	mod.mtx.Unlock()
}

func (mod *module) lookupToken(token cipherset.Token) (source, target *e3x.Exchange) {
	mod.mtx.RLock()
	source = mod.packetRoutes[token]
	target = mod.handshakeRoutes[token]
	mod.mtx.RUnlock()
	return
}

func (mod *module) on_exchange_closed(e *e3x.Endpoint, x *e3x.Exchange, reason error) error {
	mod.mtx.Lock()
	defer mod.mtx.Unlock()

	for token, exchange := range mod.packetRoutes {
		if exchange == x {
			delete(mod.packetRoutes, token)
			delete(mod.handshakeRoutes, token)
		}
	}

	for token, exchange := range mod.handshakeRoutes {
		if exchange == x {
			delete(mod.packetRoutes, token)
			delete(mod.handshakeRoutes, token)
		}
	}

	return nil
}

func (mod *module) on_dropped_packet(e *e3x.Endpoint, x *e3x.Exchange, msg []byte, pipe *e3x.Pipe, reason error) error {
	var (
		token          = cipherset.ExtractToken(msg)
		source, target = mod.lookupToken(token)
	)

	// not a bridged message
	if source == nil {
		return nil
	}
	if len(msg) < 2 {
		return nil
	}

	// detect message type
	var (
		msgtype = "PKT"
		ex      = source
	)
	if msg[0] == 0 && msg[1] == 1 {
		msgtype = "HDR"
		ex = target
	}

	// handle bridged message
	dst := ex.ActivePipe()
	if dst == pipe {
		return nil
	}

	_, err := dst.Write(msg)
	if err != nil {
		mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %s %x %s error=%s\x1B[0m", msgtype, ex, token, dst.RemoteAddr(), err)
		return nil
	} else {
		mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %s %x %s\x1B[0m", msgtype, ex, token, dst.RemoteAddr())
		return e3x.ErrStopPropagation
	}
}
