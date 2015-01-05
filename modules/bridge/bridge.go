package bridge

import (
	"io"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/internal/util/logs"
)

type Config struct {
	DisableRouter bool
	AllowPeer     func(from, to hashname.H) bool
	AllowConnect  func(from, via hashname.H) bool
}

type Bridge interface {
	RouteToken(token cipherset.Token, source, target *e3x.Exchange)
	BreakRoute(token cipherset.Token)
}

type module struct {
	mtx             sync.RWMutex
	e               *e3x.Endpoint
	config          Config
	peerListener    *e3x.Listener
	connectListener *e3x.Listener
	pending         map[hashname.H]*pendingIntroduction
	packetRoutes    map[cipherset.Token]*e3x.Exchange
	handshakeRoutes map[cipherset.Token]*e3x.Exchange
	log             *logs.Logger
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

const moduleKey = moduleKeyType("bridge")

func Module(config Config) e3x.EndpointOption {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, newBridge(e, config))(e)
	}
}

func FromEndpoint(e *e3x.Endpoint) Bridge {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}
	return mod.(*module)
}

func newBridge(e *e3x.Endpoint, config Config) *module {
	return &module{
		e:               e,
		config:          config,
		pending:         make(map[hashname.H]*pendingIntroduction),
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
