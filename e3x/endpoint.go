package e3x

import (
	"errors"
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

	cTerminate       chan struct{}
	cReceived        chan opReceived
	cDialExchange    chan *opDialExchange
	cRegisterChannel chan *opRegisterChannel
	cDeliverPacket   chan *opDeliverPacket
	cReceivePacket   chan *opReceivePacket
	cCloseChannel    chan *opCloseChannel
	cLookupAddr      chan *opLookupAddr
	cEventIn         chan events.E
	tokens           map[cipherset.Token]*exchange
	hashnames        map[hashname.H]*exchange
	scheduler        *scheduler.Scheduler
	handlers         map[string]Handler
	subscribers      events.Hub
}

type Handler interface {
	ServeTelehash(ch *Channel)
}

type HandlerFunc func(ch *Channel)

func (h HandlerFunc) ServeTelehash(ch *Channel) { h(ch) }

type opReceived struct {
	pkt  *lob.Packet
	data []byte
	addr transports.Addr
}

type opDialExchange struct {
	addr *Addr
	cErr chan error
}

type opLookupAddr struct {
	hashname hashname.H
	cAddr    chan *Addr
}

func New(keys cipherset.Keys, tc transports.Config) *Endpoint {
	return &Endpoint{keys: keys, transportConfig: tc, handlers: make(map[string]Handler)}
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

	e.tokens = make(map[cipherset.Token]*exchange)
	e.hashnames = make(map[hashname.H]*exchange)
	e.cReceived = make(chan opReceived)
	e.cDialExchange = make(chan *opDialExchange)
	e.cRegisterChannel = make(chan *opRegisterChannel)
	e.cDeliverPacket = make(chan *opDeliverPacket)
	e.cReceivePacket = make(chan *opReceivePacket)
	e.cCloseChannel = make(chan *opCloseChannel)
	e.cLookupAddr = make(chan *opLookupAddr)
	e.cTerminate = make(chan struct{}, 1)
	e.cEventIn = make(chan events.E)

	e.scheduler = scheduler.New()
	e.scheduler.Start()

	t, err := e.transportConfig.Open(e.cEventIn)
	if err != nil {
		e.err = err
		return err
	}
	e.transport = t

	e.wg.Add(1)
	go e.run_receiver()

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
	select {
	case e.cTerminate <- struct{}{}:
	default:
	}

	e.err = e.transport.Close()

	if e.state == RunningEndpointState {
		e.state = TerminatedEndpointState
	} else {
		e.state = BrokenEndpointState
	}

	e.scheduler.Stop()

	e.wg.Wait()

	close(e.cEventIn)

	return e.err
}

func (e *Endpoint) run() {
	defer e.wg.Done()

	for {
		select {

		case op := <-e.scheduler.C:
			op.Exec()

		case <-e.cTerminate:
			e.cTerminate <- struct{}{}
			return

		case op := <-e.cDialExchange:
			op.cErr <- e.dial(op)

		case op := <-e.cReceived:
			e.received(op)

		case op := <-e.cRegisterChannel:
			op.cErr <- e.register_channel(op)

		case op := <-e.cDeliverPacket:
			op.ch.deliver_packet(op)

		case op := <-e.cReceivePacket:
			op.ch.receive_packet(op)

		case op := <-e.cCloseChannel:
			op.ch.close(op)

		case op := <-e.cLookupAddr:
			e.lookup_addr(op)

		case evt := <-e.cEventIn:
			e.subscribers.Emit(evt)

		}
	}
}

func (e *Endpoint) run_receiver() {
	defer e.wg.Done()

	for {
		var buf = bufpool.GetBuffer()
		n, addr, err := e.transport.Receive(buf)
		if err == transports.ErrClosed {
			bufpool.PutBuffer(buf)
			break
		}
		if err != nil {
			bufpool.PutBuffer(buf)
			continue // report error
		}

		e.cReceived <- opReceived{nil, buf[:n], addr}
	}
}

func (e *Endpoint) received(op opReceived) {
	defer bufpool.PutBuffer(op.data)

	pkt, err := lob.Decode(op.data)
	if err != nil {
		// drop
		return
	}

	op.pkt = pkt

	if len(pkt.Head) == 1 {
		e.received_handshake(op)
		return
	}

	if len(pkt.Head) == 0 {
		e.received_packet(pkt, op.addr)
		return
	}

	// drop
}

func (e *Endpoint) received_handshake(op opReceived) {
	var (
		handshake cipherset.Handshake
		token     cipherset.Token
		hn        hashname.H
		csid      uint8
		err       error
	)

	if len(op.pkt.Body) < 4+16 {
		return // DROP
	}

	if len(op.pkt.Head) != 1 {
		return // DROP
	}

	csid = op.pkt.Head[0]

	_, handshake, err = cipherset.DecryptHandshake(csid, e.key_for_cs(csid), op.pkt.Body)
	if err != nil {
		return // drop
	}

	token = handshake.Token()
	hn, err = hashname.FromKeyAndIntermediates(csid, handshake.PublicKey().Bytes(), handshake.Parts())
	if err != nil {
		return // DROP
	}

	// find / create exchange
	ex, found := e.hashnames[hn]
	if !found {
		ex = newExchange(e)
		ex.hashname = hn
		ex.token = token
	}

	valid := ex.received_handshake(op, handshake)
	// tracef("ReceivedHandshake(%s) => %v", op.addr, valid)

	if valid {
		if !found {
			ex.reset_expire()
			ex.reschedule_handshake()
			e.tokens[token] = ex
			e.hashnames[hn] = ex
			e.subscribers.Emit(&ExchangeOpenedEvent{hn, false})
		} else if e.tokens[token] == nil {
			ex.reset_expire()
			e.tokens[token] = ex
			e.subscribers.Emit(&ExchangeOpenedEvent{hn, true})
		}
	}
}

func (e *Endpoint) received_packet(pkt *lob.Packet, addr transports.Addr) {
	var (
		token cipherset.Token
	)

	if len(pkt.Body) < 16 {
		// tracef("drop // to short")
		return //drop
	}

	copy(token[:], pkt.Body[:16])
	x := e.tokens[token]
	if x == nil {
		// tracef("drop no token")
		return // drop
	}

	x.received_packet(pkt)
}

func (e *Endpoint) deliver(pkt *lob.Packet, addr transports.Addr) error {
	data, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	return e.transport.Deliver(data, addr)
}

func (e *Endpoint) DialExchange(addr *Addr) error {
	op := opDialExchange{addr, make(chan error)}
	e.cDialExchange <- &op
	return waitForError(op.cErr)
}

func (e *Endpoint) dial(op *opDialExchange) error {
	if x, found := e.hashnames[op.addr.hashname]; found {
		if x.state == dialingExchangeState {
			x.qDial = append(x.qDial, op)
			return errDeferred
		}
		if x.state == openedExchangeState {
			return nil
		}
		panic("unreachable")
	}

	var (
		csid   = cipherset.SelectCSID(e.keys, op.addr.keys)
		x      = newExchange(e)
		cipher cipherset.State
		err    error
	)

	x.hashname = op.addr.hashname
	x.csid = csid
	x.keys = op.addr.keys
	x.parts = op.addr.parts

	cipher, err = cipherset.NewState(csid, e.key_for_cs(csid))
	if err != nil {
		return err
	}
	x.cipher = cipher

	err = cipher.SetRemoteKey(op.addr.keys[csid])
	if err != nil {
		return err
	}

	for _, addr := range op.addr.addrs {
		x.addressBook.AddAddress(addr)
	}
	// tracef("Address Book: %s", x.addressBook.KnownAddresses())

	err = x.deliver_handshake(0, nil)
	if err != nil {
		return err
	}

	x.state = dialingExchangeState
	x.reset_break()
	x.reset_expire()
	e.hashnames[op.addr.hashname] = x
	x.qDial = append(x.qDial, op)
	return errDeferred
}

func (e *Endpoint) key_for_cs(csid uint8) cipherset.Key {
	return e.keys[csid]
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
	ex, found := e.hashnames[op.hashname]
	if !found || ex == nil {
		op.cAddr <- nil
		return
	}

	addr, err := NewAddr(ex.knownKeys(), ex.knownParts(), ex.addressBook.KnownAddresses())
	if err != nil {
		tracef("error: %s", err)
		op.cAddr <- nil
		return
	}

	op.cAddr <- addr
}

func waitForError(c <-chan error) error {
	for err := range c {
		if err != errDeferred {
			return err
		}
	}
	panic("unreachable")
}
