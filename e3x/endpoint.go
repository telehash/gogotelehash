package e3x

import (
	"errors"
	"sync"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
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

	keys       cipherset.Keys
	transports transports.Manager

	cTerminate chan struct{}
	cReceived  chan opReceived
	cDial      chan *opDial
	// outboundHigh <-chan *lob.Packet // channels -> endpoint (-> transports)
	tokens    map[cipherset.Token]*exchange
	hashnames map[hashname.H]*exchange
}

type opReceived struct {
	pkt  *lob.Packet
	data []byte
	addr transports.ResolvedAddr
}

type opDial struct {
	hn    hashname.H
	keys  cipherset.Keys
	addrs []transports.ResolvedAddr
	cErr  chan error
}

func New(keys cipherset.Keys) *Endpoint {
	return &Endpoint{keys: keys}
}

func (e *Endpoint) AddTransport(t transports.Transport) {
	e.transports.AddTransport(t)
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
	e.cDial = make(chan *opDial)
	e.cTerminate = make(chan struct{}, 1)

	err := e.transports.Start()
	if err != nil {
		e.err = err
		return err
	}

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

	e.err = e.transports.Stop()

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
			e.cTerminate <- struct{}{}
			return

		case op := <-e.cDial:
			op.cErr <- e.dial(op)

		case op := <-e.cReceived:
			// handle inbound packet
			e.received(op)

			// case pkt := <-e.outboundHigh:
			//   // hanndle outbound packet
			//   e.handle_outbound(pkt)

		}
	}
}

func (e *Endpoint) run_receiver() {
	defer e.wg.Done()

	for {
		pkt, addr, err := e.transports.Receive()
		if err == transports.ErrManagerTerminated {
			break
		}
		if err != nil {
			continue // report error
		}

		e.cReceived <- opReceived{nil, pkt, addr}
	}
}

func (e *Endpoint) received(op opReceived) {
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
		token cipherset.Token
	)

	if len(op.pkt.Body) < 4+16 {
		return // DROP
	}

	// extract TOKEN
	copy(token[:], op.pkt.Body[4:4+16])

	// find / create exchange
	ex, found := e.tokens[token]
	if !found {
		ex = &exchange{endpoint: e, token: token}
	}

	valid := ex.received_handshake(op)

	if valid && !found {
		e.tokens[token] = ex
		e.hashnames[ex.hashname] = ex
	}

	if valid {
		e.transports.Associate(ex.hashname, op.addr)
	}
}

func (e *Endpoint) received_packet(pkt *lob.Packet, addr transports.ResolvedAddr) {

}

func (e *Endpoint) handle_outbound(pkt *lob.Packet) {

}

func (e *Endpoint) deliver(pkt *lob.Packet, addr transports.Addr) error {
	data, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	return e.transports.Deliver(data, addr)
}

func (e *Endpoint) Dial(keys cipherset.Keys, addrs []transports.ResolvedAddr) error {
	hn, err := hashname.FromKeys(keys)
	if err != nil {
		return err
	}

	op := opDial{hn, keys, addrs, make(chan error)}
	e.cDial <- &op
	return waitForError(op.cErr)
}

func (e *Endpoint) dial(op *opDial) error {
	if x, found := e.hashnames[op.hn]; found {
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
		csid   = cipherset.SelectCSID(e.keys, op.keys)
		x      = &exchange{endpoint: e, hashname: op.hn, csid: csid}
		cipher cipherset.State
		err    error
	)

	cipher, err = cipherset.NewState(csid, e.key_for_cs(csid), true)
	if err != nil {
		return err
	}
	x.cipher = cipher

	err = cipher.SetRemoteKey(op.keys[csid])
	if err != nil {
		return err
	}

	for _, addr := range op.addrs {
		e.transports.Associate(op.hn, addr)
	}

	err = x.deliver_handshake()
	if err != nil {
		return err
	}

	e.hashnames[op.hn] = x
	x.qDial = append(x.qDial, op)
	return errDeferred
}

func (e *Endpoint) key_for_cs(csid uint8) cipherset.Key {
	return e.keys[csid]
}

func waitForError(c <-chan error) error {
	for err := range c {
		if err != errDeferred {
			return err
		}
	}
	panic("unreachable")
}
