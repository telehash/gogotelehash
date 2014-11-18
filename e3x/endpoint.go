package e3x

import (
	"os"
	"sync"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/bufpool"
	"github.com/telehash/gogotelehash/util/logs"
)

type endpointState uint8

const (
	endpointStateUnknown endpointState = iota
	endpointStateRunning
	endpointStateTerminated
	endpointStateBroken
)

// Endpoint represents a Telehash endpoint.
type Endpoint struct {
	mtx   sync.Mutex
	state endpointState
	err   error

	hashname        hashname.H
	keys            cipherset.Keys
	log             *logs.Logger
	transportConfig transports.Config
	transport       transports.Transport
	modules         map[interface{}]Module

	cTerminate chan struct{}
	tokens     map[cipherset.Token]*Exchange
	hashnames  map[hashname.H]*Exchange
	listeners  map[string]*Listener
}

type opRead struct {
	msg []byte
	src transports.Addr
	err error
}

func New(keys cipherset.Keys, tc transports.Config) *Endpoint {
	e := &Endpoint{
		keys:            keys,
		transportConfig: tc,
		listeners:       make(map[string]*Listener),
		modules:         make(map[interface{}]Module),
	}

	if e.keys == nil {
		keys, err := cipherset.GenerateKeys()
		if err != nil {
			panic(err)
		}

		e.keys = keys
	}

	var err error
	e.hashname, err = hashname.FromKeys(e.keys)
	if err != nil {
		panic(err)
	}

	e.log = logs.Module("e3x").From(e.hashname)

	observers := &modObservers{}
	observers.Register(e.onExchangeClosed)

	e.Use(modObserversKey, observers)
	e.Use(modForgetterKey, &modForgetter{e})
	e.Use(modTransportsKey, &modTransports{e})

	return e
}

// Listen makes a new channel listener.
func (e *Endpoint) Listen(typ string, reliable bool) *Listener {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if _, f := e.listeners[typ]; f {
		panic("listener is already registered: " + typ)
	}

	l := newListener(e, typ, reliable, 0)
	e.listeners[typ] = l
	return l
}

func (e *Endpoint) listener(channelType string) *Listener {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	return e.listeners[channelType]
}

func (e *Endpoint) unregisterListener(channelType string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	delete(e.listeners, channelType)
}

func (e *Endpoint) LocalHashname() hashname.H {
	return e.hashname
}

func (e *Endpoint) LocalIdentity() (*Identity, error) {
	return NewIdentity(e.keys, nil, e.transport.LocalAddresses())
}

func (e *Endpoint) Start() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	err := e.start()
	if err != nil {
		e.stop()
		return err
	}

	return nil
}

func (e *Endpoint) start() error {
	if e.state == endpointStateBroken {
		return e.err
	}

	if e.state != endpointStateUnknown {
		panic("e3x: Endpoint cannot be started more than once")
	}

	e.tokens = make(map[cipherset.Token]*Exchange)
	e.hashnames = make(map[hashname.H]*Exchange)
	e.cTerminate = make(chan struct{}, 1)

	e.mtx.Unlock()
	for _, mod := range e.modules {
		err := mod.Init()
		if err != nil {
			e.mtx.Lock()
			e.err = err
			return err
		}
	}
	e.mtx.Lock()

	t, err := e.transportConfig.Open()
	if err != nil {
		e.err = err
		return err
	}
	e.transport = t
	go e.runReader()

	e.mtx.Unlock()
	for _, mod := range e.modules {
		err := mod.Start()
		if err != nil {
			e.mtx.Lock()
			e.err = err
			return err
		}
	}
	e.mtx.Lock()

	return nil
}

func (e *Endpoint) Stop() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	return e.stop()
}

func (e *Endpoint) stop() error {
	e.mtx.Unlock()
	for _, mod := range e.modules {
		err := mod.Stop()
		if err != nil {
			e.mtx.Lock()
			e.err = err
			return err
		}
	}
	e.mtx.Lock()

	for _, x := range e.hashnames {
		x.onBreak()
	}
	for _, x := range e.tokens {
		x.onBreak()
	}

	e.transport.Close() //TODO handle err

	if e.state == endpointStateRunning {
		e.state = endpointStateTerminated
	} else {
		e.state = endpointStateBroken
	}

	return e.err
}

func (e *Endpoint) runReader() {
	for {
		buf := bufpool.GetBuffer()
		n, src, err := e.transport.ReadMessage(buf)
		if err == transports.ErrClosed {
			return
		}

		e.received(opRead{buf[:n], src, err})
	}
}

func (e *Endpoint) onExchangeClosed(event *ExchangeClosedEvent) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	x := e.hashnames[event.Exchange.remoteIdent.Hashname()]
	if x != nil {
		delete(e.hashnames, x.remoteIdent.Hashname())
		delete(e.tokens, x.LocalToken())
	}

}

func (e *Endpoint) received(op opRead) {
	if len(op.msg) >= 3 && op.msg[0] == 0 && op.msg[1] == 1 {
		e.mtx.Lock()
		defer e.mtx.Unlock()

		e.receivedHandshake(op)
		return
	}

	if len(op.msg) >= 2 && op.msg[0] == 0 && op.msg[1] == 0 {
		e.receivedPacket(op)
		return
	}

	// drop
}

func (e *Endpoint) receivedHandshake(op opRead) {
	var (
		x          *Exchange
		localIdent *Identity
		csid       uint8
		localKey   cipherset.Key
		handshake  cipherset.Handshake
		token      cipherset.Token
		hn         hashname.H
		err        error
	)

	token = cipherset.ExtractToken(op.msg)
	if token == cipherset.ZeroToken {
		return // drop
	}

	localIdent, err = e.LocalIdentity()
	if err != nil {
		return // drop
	}

	csid = uint8(op.msg[2])
	localKey = localIdent.keys[csid]
	if localKey == nil {
		return // drop
	}

	handshake, err = cipherset.DecryptHandshake(csid, localKey, op.msg[3:])
	if err != nil {
		return // drop
	}

	hn, err = hashname.FromKeyAndIntermediates(csid,
		handshake.PublicKey().Public(), handshake.Parts())
	if err != nil {
		return // drop
	}

	x = e.hashnames[hn]
	if x != nil {
		x.received(op)
		return
	}

	x, err = newExchange(localIdent, nil, handshake, e, ObserversFromEndpoint(e), e.log)
	if err != nil {
		return // drop
	}

	e.hashnames[hn] = x
	e.tokens[x.LocalToken()] = x
	x.state = ExchangeDialing
	x.received(op)
}

func (e *Endpoint) receivedPacket(op opRead) {
	var (
		token = cipherset.ExtractToken(op.msg)
	)

	if token == cipherset.ZeroToken {
		return // drop
	}

	e.mtx.Lock()
	x := e.tokens[token]
	e.mtx.Unlock()
	if x == nil {
		return // drop
	}

	e.log.To(x.RemoteHashname()).Module("e3x.tx").
		Printf("\x1B[36mRCV\x1B[0m token=%x from=%s", token, op.src)

	x.received(op)
}

func (e *Endpoint) Identify(i Identifier) (*Identity, error) {
	return i.Identify(e)
}

// Dial will lookup the identity of identifier, get the exchange for the identity
// and dial the exchange.
func (e *Endpoint) Dial(identifier Identifier) (*Exchange, error) {
	if identifier == nil || e == nil {
		return nil, os.ErrInvalid
	}

	var (
		identity *Identity
		x        *Exchange
		err      error
	)

	identity, err = e.Identify(identifier)
	if err != nil {
		return nil, err
	}

	x, err = e.GetExchange(identity)
	if err != nil {
		return nil, err
	}

	err = x.Dial()
	if err != nil {
		return nil, err
	}

	return x, nil
}

// GetExchange returns the exchange for identity. If the exchange already exists
// it is simply returned otherwise a new exchange is created and registered.
// Not that this GetExchange does not Dial.
func (e *Endpoint) GetExchange(identity *Identity) (*Exchange, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	// Check for existing exchange
	if x, found := e.hashnames[identity.hashname]; found && x != nil {
		return x, nil
	}

	var (
		localIdent *Identity
		x          *Exchange

		err error
	)

	// Get local identity
	localIdent, err = e.LocalIdentity()
	if err != nil {
		return nil, err
	}

	// Make a new exchange struct
	x, err = newExchange(localIdent, identity, nil, e, ObserversFromEndpoint(e), e.log)
	if err != nil {
		return nil, err
	}

	// register the new exchange
	e.tokens[x.LocalToken()] = x
	e.hashnames[identity.hashname] = x

	return x, nil
}

func (e *Endpoint) Use(key interface{}, mod Module) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if e.state != endpointStateUnknown {
		panic("(*Endpoint).Use() can only be called when Endpoint is not yet started.")
	}
	if _, found := e.modules[key]; found {
		panic("This module is already registered.")
	}
	e.modules[key] = mod
}

func (e *Endpoint) Module(key interface{}) Module {
	return e.modules[key]
}

func (e *Endpoint) writeMessage(p []byte, dst transports.Addr) error {
	return e.transport.WriteMessage(p, dst)
}
