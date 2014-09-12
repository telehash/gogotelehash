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
	localAddresses  transports.AddrSet

	cTerminate       chan struct{}
	cDialExchange    chan *opDialExchange
	cRegisterChannel chan *opRegisterChannel
	cLookupAddr      chan *opLookupAddr
	cTransportRead   chan transports.ReadOp
	cTransportWrite  chan transports.WriteOp
	cTransportDone   <-chan struct{}
	cEventIn         chan events.E
	tokens           map[cipherset.Token]*exchangeEntry
	hashnames        map[hashname.H]*exchangeEntry
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
	pkt *lob.Packet
	transports.ReadOp
}

type opDialExchange struct {
	addr *Addr
	cErr chan error
}

type opLookupAddr struct {
	hashname hashname.H
	cAddr    chan *Addr
}

type exchangeEntry struct {
	x              *exchange
	cReadPacket    chan transports.ReadOp
	cReadHandshake chan opHandshakeRead
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
	return NewAddr(e.keys, nil, e.localAddresses)
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
	e.cDialExchange = make(chan *opDialExchange)
	e.cRegisterChannel = make(chan *opRegisterChannel)
	e.cLookupAddr = make(chan *opLookupAddr)
	e.cTerminate = make(chan struct{}, 1)
	e.cTransportWrite = make(chan transports.WriteOp)
	e.cTransportRead = make(chan transports.ReadOp)
	e.cEventIn = make(chan events.E)

	e.scheduler = scheduler.New()
	e.scheduler.Start()

	t, err := e.transportConfig.Open()
	if err != nil {
		e.err = err
		return err
	}
	e.transport = t
	e.cTransportDone = t.Run(e.cTransportWrite, e.cTransportRead, e.cEventIn)

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

		case <-e.cTransportDone:
			close(e.cTransportRead)
			close(e.cEventIn)
			e.cTransportRead = nil
			e.cTransportWrite = nil
			e.cEventIn = nil
			return

		case <-e.cTerminate:
			close(e.cTransportWrite)

		case op := <-e.cDialExchange:
			op.cErr <- e.dial(op)

		case op := <-e.cTransportRead:
			e.received(opReceived{nil, op})

		case op := <-e.cRegisterChannel:
			op.cErr <- e.register_channel(op)

		// case op := <-e.cExchangeWrite:
		// 	op.x.deliver_packet(op)

		case op := <-e.cLookupAddr:
			e.lookup_addr(op)

		case evt := <-e.cEventIn:
			if x, ok := evt.(*transports.NetworkChangeEvent); ok && x != nil {
				for _, addr := range x.Up {
					e.localAddresses.Add(addr)
				}
				for _, addr := range x.Down {
					e.localAddresses.Remove(addr)
				}
			}
			e.subscribers.Emit(evt)

		}
	}
}

func (e *Endpoint) received(op opReceived) {
	defer bufpool.PutBuffer(op.Msg)

	pkt, err := lob.Decode(op.Msg)
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
		e.received_packet(pkt, op.Src)
		return
	}

	// drop
}

func (e *Endpoint) received_handshake(op opReceived) {
	var (
		x         *exchange
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
	hn, err = hashname.FromKeyAndIntermediates(csid, handshake.PublicKey().Public(), handshake.Parts())
	if err != nil {
		return // DROP
	}

	// find / create exchange
	entry, found := e.hashnames[hn]
	if !found {
		cReadPacket := make(chan transports.ReadOp)
		cReadHandshake := make(chan opHandshakeRead)
		x = newExchange(hn, token, e.cTransportWrite, cReadPacket, cReadHandshake)
		entry = &exchangeEntry{
			cReadPacket:    cReadPacket,
			cReadHandshake: cReadHandshake,
			x:              x,
		}

		e.tokens[token] = entry
		e.hashnames[hn] = entry

		go x.run()
	} else {
		if e.tokens[token] == nil {
			e.tokens[token] = entry
		}

		x = entry.x
	}

	entry.cReadHandshake <- opHandshakeRead{handshake, op.Src}
	// valid := x.received_handshake(op, handshake)
	// tracef("ReceivedHandshake(%s) => %v", op.addr, valid)

	// if valid {
	//   if !found {
	//     ex.reset_expire()
	//     ex.reschedule_handshake()
	//     e.tokens[token] = ex
	//     e.hashnames[hn] = ex
	//     e.subscribers.Emit(&ExchangeOpenedEvent{hn, false})
	//   } else if e.tokens[token] == nil {
	//     ex.reset_expire()
	//     e.subscribers.Emit(&ExchangeOpenedEvent{hn, true})
	//   }
	// }
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
	c := e.tokens[token]
	if c == nil {
		// tracef("drop no token")
		return // drop
	}

	c.cReadPacket <- transports.ReadOp{pkt.Body, addr}
}

func (e *Endpoint) deliver(pkt *lob.Packet, addr transports.Addr) error {
	data, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	op := transports.WriteOp{data, addr, make(chan error)}
	e.cTransportWrite <- op
	return <-op.C
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
	entry, found := e.hashnames[op.hashname]
	if !found || entry == nil {
		op.cAddr <- nil
		return
	}

	ex := entry.x

	addr, err := NewAddr(ex.knownKeys(), ex.knownParts(), ex.addressBook.KnownAddresses())
	if err != nil {
		tracef("error: %s", err)
		op.cAddr <- nil
		return
	}

	op.cAddr <- addr
}

func (e *Endpoint) register_channel(op *opRegisterChannel) error {
	x := e.hashnames[op.ch.hashname]
	if x == nil || x.state != openedExchangeState {
		return UnreachableEndpointError(op.ch.hashname)
	}

	return x.register_channel(op.ch)
}

func waitForError(c <-chan error) error {
	for err := range c {
		if err != errDeferred {
			return err
		}
	}
	panic("unreachable")
}
