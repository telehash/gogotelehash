package e3x

import (
	"errors"
	"os"
	"sync"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/bufpool"
	"bitbucket.org/simonmenke/go-telehash/util/logs"
)

type EndpointState uint8

const (
	UnknownEndpointState EndpointState = iota
	RunningEndpointState
	TerminatedEndpointState
	BrokenEndpointState
)

var errDeferred = errors.New("e3x: deferred operation")

type Endpoint struct {
	stateMtx sync.Mutex
	wg       sync.WaitGroup
	state    EndpointState
	err      error

	hashname        hashname.H
	keys            cipherset.Keys
	log             *logs.Logger
	transportConfig transports.Config
	transport       transports.Transport
	modules         map[interface{}]Module

	cTerminate     chan struct{}
	cMakeExchange  chan *opMakeExchange
	cLookupIdent   chan *opLookupIdent
	cTransportRead chan opRead
	tokens         map[cipherset.Token]*exchangeEntry
	hashnames      map[hashname.H]*exchangeEntry
	handlers       map[string]Handler
}

type Handler interface {
	ServeTelehash(ch *Channel)
}

type HandlerFunc func(ch *Channel)

func (h HandlerFunc) ServeTelehash(ch *Channel) { h(ch) }

type opReceived struct {
	pkt *lob.Packet
	opRead
}

type opMakeExchange struct {
	ident *Ident
	x     *Exchange
	cErr  chan error
}

type opLookupIdent struct {
	hashname hashname.H
	cIdent   chan *Ident
}

type opRead struct {
	msg []byte
	src transports.Addr
	err error
}

type exchangeEntry struct {
	x *Exchange
}

func New(keys cipherset.Keys, tc transports.Config) *Endpoint {
	e := &Endpoint{
		keys:            keys,
		transportConfig: tc,
		handlers:        make(map[string]Handler),
		modules:         make(map[interface{}]Module),
	}

	var err error
	e.hashname, err = hashname.FromKeys(e.keys)
	if err != nil {
		panic(err)
	}

	e.log = logs.Module("e3x").From(e.hashname)

	observers := &modObservers{}
	observers.Register(e.on_exchange_closed)

	e.Use(modObserversKey, observers)
	e.Use(modForgetterKey, &modForgetter{e})
	e.Use(modTransportsKey, &modTransports{e})

	return e
}

func (e *Endpoint) AddHandler(typ string, h Handler) {
	e.handlers[typ] = h
}

func (e *Endpoint) LocalHashname() hashname.H {
	return e.hashname
}

func (e *Endpoint) LocalIdent() (*Ident, error) {
	return NewIdent(e.keys, nil, e.transport.LocalAddresses())
}

func (e *Endpoint) Start() error {
	e.stateMtx.Lock()
	defer e.stateMtx.Unlock()

	err := e.start()
	if err != nil {
		e.stop()
		return err
	}

	return nil
}

func (e *Endpoint) start() error {
	if e.state == BrokenEndpointState {
		return e.err
	}

	if e.state != UnknownEndpointState {
		panic("e3x: Endpoint cannot be started more than once")
	}

	e.tokens = make(map[cipherset.Token]*exchangeEntry)
	e.hashnames = make(map[hashname.H]*exchangeEntry)
	e.cMakeExchange = make(chan *opMakeExchange)
	e.cLookupIdent = make(chan *opLookupIdent)
	e.cTerminate = make(chan struct{}, 1)
	e.cTransportRead = make(chan opRead)

	for _, mod := range e.modules {
		err := mod.Init()
		if err != nil {
			e.err = err
			return err
		}
	}

	t, err := e.transportConfig.Open()
	if err != nil {
		e.err = err
		return err
	}
	e.transport = t
	go e.runReader()

	for _, mod := range e.modules {
		err := mod.Start()
		if err != nil {
			e.err = err
			return err
		}
	}

	e.wg.Add(1)
	go e.run()

	return nil
}

func (e *Endpoint) Stop() error {
	e.stateMtx.Lock()
	defer e.stateMtx.Unlock()

	return e.stop()
}

func (e *Endpoint) stop() error {
	for _, mod := range e.modules {
		err := mod.Stop()
		if err != nil {
			e.err = err
			return err
		}
	}

	select {
	case <-e.cTerminate: // closed
	default:
		close(e.cTerminate)
	}

	if e.state == RunningEndpointState {
		e.state = TerminatedEndpointState
	} else {
		e.state = BrokenEndpointState
	}

	e.wg.Wait()

	return e.err
}

func (e *Endpoint) run() {
	defer e.wg.Done()

	for {
		select {

		case <-e.cTerminate:
			for _, e := range e.hashnames {
				e.x.on_break()
			}
			for _, e := range e.tokens {
				e.x.on_break()
			}
			e.transport.Close() //TODO handle err
			return

		case op := <-e.cMakeExchange:
			e.dial(op)

		case op := <-e.cTransportRead:
			e.received(op)

		case op := <-e.cLookupIdent:
			e.lookupIdent(op)

		}
	}
}

func (e *Endpoint) runReader() {
	for {
		buf := bufpool.GetBuffer()
		n, src, err := e.transport.ReadMessage(buf)
		if err == transports.ErrClosed {
			return
		}
		e.cTransportRead <- opRead{buf[:n], src, err}
	}
}

func (e *Endpoint) on_exchange_closed(event *ExchangeClosedEvent) {

	entry := e.hashnames[event.Exchange.remoteIdent.Hashname()]
	if entry != nil {
		delete(e.hashnames, event.Exchange.remoteIdent.Hashname())
		delete(e.tokens, entry.x.token)
	}

}

func (e *Endpoint) received(op opRead) {
	if len(op.msg) >= 3 && op.msg[0] == 0 && op.msg[1] == 1 {
		e.received_handshake(op)
		return
	}

	if len(op.msg) >= 2 && op.msg[0] == 0 && op.msg[1] == 0 {
		e.received_packet(op)
	}

	// drop
}

func (e *Endpoint) received_handshake(op opRead) {
	var (
		entry      *exchangeEntry
		x          *Exchange
		localIdent *Ident
		csid       uint8
		localKey   cipherset.Key
		handshake  cipherset.Handshake
		token      cipherset.Token
		hn         hashname.H
		err        error
	)

	token = cipherset.ExtractToken(op.msg)
	if token == cipherset.ZeroToken {
		tracef("received_handshake() => drop // no token")
		return // drop
	}

	entry = e.tokens[token]
	if entry != nil {
		// tracef("received_handshake() => found token %x", token)
		entry.x.received(op)
		// tracef("received_handshake() => done %x", token)
		return
	}

	localIdent, err = e.LocalIdent()
	if err != nil {
		tracef("received_handshake() => drop // no local address")
		return // drop
	}

	csid = uint8(op.msg[2])
	localKey = localIdent.keys[csid]
	if localKey == nil {
		tracef("received_handshake() => drop // no local key")
		return // drop
	}

	handshake, err = cipherset.DecryptHandshake(csid, localKey, op.msg[3:])
	if err != nil {
		tracef("received_handshake() => drop // invalid handshake err=%s", err)
		return // drop
	}

	hn, err = hashname.FromKeyAndIntermediates(csid,
		handshake.PublicKey().Public(), handshake.Parts())
	if err != nil {
		tracef("received_handshake() => drop // invalid hashname err=%s", err)
		return // drop
	}

	entry = e.hashnames[hn]
	if entry != nil {
		// tracef("received_handshake() => found hashname %x %s", token, hn)
		e.tokens[token] = entry
		entry.x.received(op)
		// tracef("received_handshake() => done %x", token)
		return
	}

	x, err = newExchange(localIdent, nil, handshake, token,
		e.transport, ObserversFromEndpoint(e), e.handlers, e.log)
	if err != nil {
		tracef("received_handshake() => invalid exchange err=%s", err)
		return // drop
	}

	entry = &exchangeEntry{
		x: x,
	}

	// tracef("received_handshake() => registered %x %s", token, hn)
	e.hashnames[hn] = entry
	e.tokens[token] = entry
	x.state = ExchangeDialing
	x.received(op)
	// tracef("received_handshake() => done %x", token)
}

func (e *Endpoint) received_packet(op opRead) {
	var (
		token = cipherset.ExtractToken(op.msg)
	)

	if token == cipherset.ZeroToken {
		return // drop
	}

	entry := e.tokens[token]
	if entry == nil {
		tracef("unknown token")
		return // drop
	}

	e.log.To(entry.x.RemoteHashname()).Module("e3x.tx").
		Printf("\x1B[36mRCV\x1B[0m token=%x from=%s", token, op.src)

	entry.x.received(op)
}

func (e *Endpoint) Dial(ident *Ident) (*Exchange, error) {
	if ident == nil {
		return nil, os.ErrInvalid
	}

	op := opMakeExchange{ident, nil, make(chan error)}
	e.cMakeExchange <- &op
	err := <-op.cErr
	if err != nil {
		return nil, err
	}

	err = op.x.dial()
	if err != nil {
		return nil, err
	}

	return op.x, nil
}

func (e *Endpoint) dial(op *opMakeExchange) {
	if entry, found := e.hashnames[op.ident.hashname]; found {
		op.x = entry.x
		op.cErr <- nil
		return
	}

	var (
		entry      = &exchangeEntry{}
		localIdent *Ident
		x          *Exchange

		err error
	)

	localIdent, err = e.LocalIdent()
	if err != nil {
		op.cErr <- err
		return
	}

	x, err = newExchange(localIdent, op.ident, nil, cipherset.ZeroToken,
		e.transport, ObserversFromEndpoint(e), e.handlers, e.log)
	if err != nil {
		op.cErr <- err
		return
	}

	entry.x = x
	e.hashnames[op.ident.hashname] = entry

	op.x = x
	op.cErr <- nil
	return
}

func (e *Endpoint) Use(key interface{}, mod Module) {
	e.stateMtx.Lock()
	defer e.stateMtx.Unlock()
	if e.state != UnknownEndpointState {
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

func (e *Endpoint) Resolve(hn hashname.H) (*Ident, error) {
	var (
		ident *Ident
	)

	if ident == nil {
		op := opLookupIdent{hashname: hn, cIdent: make(chan *Ident)}
		e.cLookupIdent <- &op
		ident = <-op.cIdent
	}

	if ident == nil {
		return nil, ErrNoAddress
	}

	return ident, nil
}

func (e *Endpoint) lookupIdent(op *opLookupIdent) {
	entry, found := e.hashnames[op.hashname]
	if !found || entry == nil {
		op.cIdent <- nil
		return
	}

	op.cIdent <- entry.x.RemoteIdent()
}

func waitForError(c <-chan error) error {
	for err := range c {
		if err != errDeferred {
			return err
		}
	}
	panic("unreachable")
}
