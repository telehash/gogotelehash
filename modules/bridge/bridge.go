package bridge

import (
	"net"
	"sync"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/logs"
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

	e3x.TransportsFromEndpoint(mod.e).Wrap(func(c transports.Config) transports.Config {
		return transportConfig{mod, c}
	})

	e3x.ObserversFromEndpoint(mod.e).Register(mod.on_exchange_closed)

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

func (mod *module) on_exchange_closed(e *e3x.ExchangeClosedEvent) {
	mod.mtx.Lock()
	defer mod.mtx.Unlock()

	for token, x := range mod.packetRoutes {
		if e.Exchange == x {
			delete(mod.packetRoutes, token)
			delete(mod.handshakeRoutes, token)
		}
	}

	for token, x := range mod.handshakeRoutes {
		if e.Exchange == x {
			delete(mod.packetRoutes, token)
			delete(mod.handshakeRoutes, token)
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

func (t *transport) Addrs() []net.Addr {
	return t.t.Addrs()
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	conn, err := t.t.Dial(addr)
	if err != nil {
		return nil, err
	}
	return &connection{t.mod, conn}, nil
}

func (t *transport) Accept() (net.Conn, error) {
	conn, err := t.t.Accept()
	if err != nil {
		return nil, err
	}
	return &connection{t.mod, conn}, nil
}

func (t *transport) Close() error {
	return t.t.Close()
}

type connection struct {
	mod *module
	net.Conn
}

func (c *connection) Read(b []byte) (n int, err error) {
	for {
		n, err = c.Conn.Read(b)
		if err != nil {
			return n, err
		}

		buf := b[:n]

		var (
			token          = cipherset.ExtractToken(buf)
			source, target = c.mod.lookupToken(token)
		)

		// not a bridged message
		if source == nil {
			return n, err
		}
		if n <= 2 {
			return n, err
		}

		// detect message type
		var (
			msgtype = "PKT"
			ex      = source
		)
		if buf[0] == 0 && buf[1] == 1 {
			msgtype = "HDR"
			ex = target
		}

		// handle bridged message
		pipe := ex.ActivePipe()
		_, err = pipe.Write(buf)
		if err != nil {
			// TODO handle error
			c.mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %x %s error=%s\x1B[0m", msgtype, token, pipe, err)
		} else {
			c.mod.log.To(ex.RemoteHashname()).Printf("\x1B[35mFWD %s %x %s\x1B[0m", msgtype, token, pipe)
		}

		// continue reading messages
	}
}
