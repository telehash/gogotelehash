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
	"bitbucket.org/simonmenke/go-telehash/util/events"
	"bitbucket.org/simonmenke/go-telehash/util/scheduler"
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

	keys            cipherset.Keys
	transportConfig transports.Config
	transport       transports.Transport
	modules         map[interface{}]Module

	cTerminate     chan struct{}
	cMakeExchange  chan *opMakeExchange
	cLookupAddr    chan *opLookupAddr
	cTransportRead chan opRead
	cEventIn       chan events.E
	tokens         map[cipherset.Token]*exchangeEntry
	hashnames      map[hashname.H]*exchangeEntry
	scheduler      *scheduler.Scheduler
	handlers       map[string]Handler
	subscribers    events.Hub
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
	addr *Addr
	x    *Exchange
	cErr chan error
}

type opLookupAddr struct {
	hashname hashname.H
	cAddr    chan *Addr
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

	e.Use(modForgetterKey, &modForgetter{e})
	e.Use(modTransportsKey, &modTransports{e})

	return e
}

func (e *Endpoint) Subscribe(c chan<- events.E) {
	e.subscribers.Subscribe(c)
}

func (e *Endpoint) Unsubscribe(c chan<- events.E) {
	e.subscribers.Unubscribe(c)
}

func (e *Endpoint) AddHandler(typ string, h Handler) {
	e.handlers[typ] = h
}

func (e *Endpoint) LocalAddr() (*Addr, error) {
	return NewAddr(e.keys, nil, e.transport.LocalAddresses())
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
	e.cLookupAddr = make(chan *opLookupAddr)
	e.cTerminate = make(chan struct{}, 1)
	e.cTransportRead = make(chan opRead)
	e.cEventIn = make(chan events.E, 10)
	e.scheduler = scheduler.New()

	for _, mod := range e.modules {
		err := mod.Init()
		if err != nil {
			e.err = err
			return err
		}
	}

	e.scheduler.Start()

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

	e.scheduler.Stop()

	e.wg.Wait()

	return e.err
}

func (e *Endpoint) run() {
	defer e.wg.Done()

	for {
		select {

		case op := <-e.scheduler.C:
			op.Exec()

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

		case op := <-e.cLookupAddr:
			e.lookup_addr(op)

		case evt := <-e.cEventIn:
			e.handle_event(evt)

		}

		// flush events
		for more := true; more; {
			select {
			case evt := <-e.cEventIn:
				e.handle_event(evt)
			default:
				more = false
			}
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

func (e *Endpoint) handle_event(evt events.E) {

	if cevt, ok := evt.(*ExchangeClosedEvent); ok && cevt != nil {
		entry := e.hashnames[cevt.Exchange.remoteAddr.Hashname()]
		if entry != nil {
			delete(e.hashnames, cevt.Exchange.remoteAddr.Hashname())
			delete(e.tokens, entry.x.token)
		}
	}

	e.subscribers.Emit(evt)
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
		entry     *exchangeEntry
		x         *Exchange
		localAddr *Addr
		csid      uint8
		localKey  cipherset.Key
		handshake cipherset.Handshake
		token     cipherset.Token
		hn        hashname.H
		err       error
	)

	token = cipherset.ExtractToken(op.msg)
	if token == cipherset.ZeroToken {
		tracef("received_handshake() => drop // no token")
		return // drop
	}

	entry = e.tokens[token]
	if entry != nil {
		tracef("received_handshake() => found token %x", token)
		entry.x.received(op)
		tracef("received_handshake() => done %x", token)
		return
	}

	localAddr, err = e.LocalAddr()
	if err != nil {
		tracef("received_handshake() => drop // no local address")
		return // drop
	}

	csid = uint8(op.msg[2])
	localKey = localAddr.keys[csid]
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
		tracef("received_handshake() => found hashname %x %s", token, hn)
		e.tokens[token] = entry
		entry.x.received(op)
		tracef("received_handshake() => done %x", token)
		return
	}

	x, err = newExchange(localAddr, nil, handshake, token,
		e.transport, e.cEventIn, e.handlers)
	if err != nil {
		tracef("received_handshake() => invalid exchange err=%s", err)
		return // drop
	}

	entry = &exchangeEntry{
		x: x,
	}

	tracef("received_handshake() => registered %x %s", token, hn)
	e.hashnames[hn] = entry
	e.tokens[token] = entry
	x.state = ExchangeDialing
	x.received(op)
	tracef("received_handshake() => done %x", token)
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

	entry.x.received(op)
}

func (e *Endpoint) Dial(addr *Addr) (*Exchange, error) {
	if addr == nil {
		return nil, os.ErrInvalid
	}

	op := opMakeExchange{addr, nil, make(chan error)}
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
	tracef("op=%v", op)
	if entry, found := e.hashnames[op.addr.hashname]; found {
		op.x = entry.x
		op.cErr <- nil
		return
	}

	var (
		entry     = &exchangeEntry{}
		localAddr *Addr
		x         *Exchange

		err error
	)

	localAddr, err = e.LocalAddr()
	if err != nil {
		op.cErr <- err
		return
	}

	x, err = newExchange(localAddr, op.addr, nil, cipherset.ZeroToken,
		e.transport, e.cEventIn, e.handlers)
	if err != nil {
		op.cErr <- err
		return
	}

	entry.x = x
	e.hashnames[op.addr.hashname] = entry

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

func (e *Endpoint) Resolve(hn hashname.H) (*Addr, error) {
	var (
		addr *Addr
	)

	if addr == nil {
		op := opLookupAddr{hashname: hn, cAddr: make(chan *Addr)}
		e.cLookupAddr <- &op
		addr = <-op.cAddr
	}

	if addr == nil {
		return nil, ErrNoAddress
	}

	return addr, nil
}

func (e *Endpoint) lookup_addr(op *opLookupAddr) {
	entry, found := e.hashnames[op.hashname]
	if !found || entry == nil {
		op.cAddr <- nil
		return
	}

	op.cAddr <- entry.x.RemoteAddr()
}

func waitForError(c <-chan error) error {
	for err := range c {
		if err != errDeferred {
			return err
		}
	}
	panic("unreachable")
}
