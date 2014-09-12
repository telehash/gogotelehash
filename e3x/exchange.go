package e3x

import (
	"math/rand"
	"time"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
)

type BrokenExchange hashname.H

func (err BrokenExchange) Error() string {
	return "e3x: broken exchange " + string(err)
}

type exchangeState uint8

const (
	unknownExchangeState exchangeState = iota
	dialingExchangeState
	openedExchangeState
	expiredExchangeState
)

type exchange struct {
	state           exchangeState
	last_seq        uint32
	next_seq        uint32
	token           cipherset.Token
	hashname        hashname.H
	keys            cipherset.Keys
	parts           cipherset.Parts
	csid            uint8
	cipher          cipherset.State
	qDial           []*opDialExchange
	next_channel_id uint32
	channels        map[uint32]*Channel
	addressBook     *addressBook

	// owned channels
	cExchangeWrite chan opExchangeWrite
	cExchangeRead  chan opExchangeRead
	cDone          chan struct{}

	// lended channels
	cTransportWrite chan<- transports.WriteOp
	cEndpointRead   <-chan transports.ReadOp
	cHandshakeRead  <-chan opHandshakeRead

	nextHandshake     int
	tExpire           *time.Timer
	tBreak            *time.Timer
	tDeliverHandshake *time.Timer

	// should be removed
	endpoint *Endpoint
}

type opExchangeWrite struct {
	pkt  *lob.Packet
	cErr chan error
}

type opExchangeRead struct {
	pkt *lob.Packet
	err error
}

type opHandshakeRead struct {
	handshake cipherset.Handshake
	src       transports.Addr
}

func newExchange(
	hashname hashname.H,
	token cipherset.Token,
	w chan<- transports.WriteOp,
	r <-chan transports.ReadOp,
	rHandshake <-chan opExchangeReadHandshake,
) *exchange {
	x := &exchange{
		hashname:        hashname,
		token:           token,
		channels:        make(map[uint32]*Channel),
		addressBook:     newAddressBook(),
		cExchangeWrite:  make(chan opExchangeWrite),
		cExchangeRead:   make(chan opExchangeRead),
		cDone:           make(chan struct{}),
		cTransportWrite: w,
		cEndpointRead:   r,
		cHandshakeRead:  rHandshake,
	}
	// x.tExpire = e.scheduler.NewEvent(x.on_expire)
	// x.tBreak = e.scheduler.NewEvent(x.on_break)
	// x.tDeliverHandshake = e.scheduler.NewEvent(x.on_deliver_handshake)
	return x
}

func (x *exchange) run() {
	defer func() {
		close(x.cDone)
		x.tBreak.Stop()
		x.tExpire.Stop()
		x.tDeliverHandshake.Stop()
		close(x.cExchangeWrite)
		close(x.cExchangeRead)
	}()

	x.tBreak = time.NewTimer(2 * 60 * time.Second)
	x.tExpire = time.NewTimer(60 * time.Second)
	x.tExpire.Stop()
	x.tDeliverHandshake = time.NewTimer(60 * time.Second)
	x.tDeliverHandshake.Stop()

	x.state = dialingExchangeState
	x.deliver_handshake(0, nil)

	for {
		var (
			cExchangeWrite = x.cExchangeWrite
			cExchangeRead  = x.cExchangeRead
		)

		select {

		case op := <-cExchangeWrite:
			x.deliver_packet(op)

		case op := <-x.cEndpointRead:
			x.received_packet(op)

		case op := <-x.cHandshakeRead:
			x.received_handshake(op)

		}

		if x.state == expiredExchangeState {
			return
		}
	}
}

func (e *exchange) knownKeys() cipherset.Keys {
	return e.keys
}

func (e *exchange) knownParts() cipherset.Parts {
	return e.parts
}

func (e *exchange) received_handshake(op opHandshakeRead) bool {
	// tracef("receiving_handshake(%p) pkt=%v", e, op.pkt)

	var (
		csid = op.handshake.CSID()
		seq  = op.handshake.At()
		err  error
	)

	if seq < e.last_seq {
		return false
	}

	if e.cipher == nil {
		key := e.endpoint.key_for_cs(csid)
		if key == nil {
			return false
		}

		e.cipher, err = cipherset.NewState(csid, key)
		if err != nil {
			return false
		}

		e.csid = csid
	}

	if csid != e.csid {
		return false
	}

	if !e.cipher.ApplyHandshake(op.handshake) {
		return false
	}

	if e.keys == nil {
		e.keys = cipherset.Keys{e.csid: op.handshake.PublicKey()}
	}
	if e.parts == nil {
		e.parts = op.handshake.Parts()
	}

	if seq > e.last_seq {
		e.deliver_handshake(seq, op.src)
		e.addressBook.AddAddress(op.src)
	} else {
		e.addressBook.ReceivedHandshake(op.src)
	}

	e.state = openedExchangeState
	e.reset_break()
	for _, op := range e.qDial {
		op.cErr <- nil
	}
	e.qDial = nil

	return true
}

func (e *exchange) deliver_handshake(seq uint32, addr transports.Addr) error {
	// tracef("delivering_handshake(%p)", e)

	var (
		o     = &lob.Packet{Head: []byte{e.csid}}
		addrs []transports.Addr
		err   error
	)

	if seq == 0 {
		seq = e.getNextSeq()
	}

	if addr != nil {
		addrs = append(addrs, addr)
	} else {
		addrs = e.addressBook.HandshakeAddresses()
		e.addressBook.NextHandshakeEpoch()
	}

	o.Body, err = e.cipher.EncryptHandshake(seq, hashname.PartsFromKeys(e.endpoint.keys))
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		e.addressBook.SentHandshake(addr)
		err = e.endpoint.deliver(o, addr) // ignore error
		if err != nil {
			tracef("error: %s %s", addr, err)
		}
	}

	e.last_seq = seq

	// determine when the next handshake must be send
	if addr == nil {
		e.reschedule_handshake()
	}

	return nil
}

func (e *exchange) reschedule_handshake() {
	if e.nextHandshake <= 0 {
		e.nextHandshake = 1
	} else if e.nextHandshake > 60 {
		e.nextHandshake = 60
	} else {
		e.nextHandshake = e.nextHandshake * 2
	}

	if n := e.nextHandshake / 3; n > 0 {
		e.nextHandshake -= rand.Intn(n)
	}

	e.tDeliverHandshake.Reset(time.Duration(e.nextHandshake) * time.Second)
}

func (e *exchange) received_packet(op transports.ReadOp) {
	pkt, err := lob.Decode(op.Msg)
	if err != nil {
		return // drop
	}

	pkt, err = e.cipher.DecryptPacket(pkt)
	if err != nil {
		return // drop
	}
	var (
		cid, hasC    = pkt.Header().GetUint32("c")
		typ, hasType = pkt.Header().GetString("type")
		_, hasSeq    = pkt.Header().GetUint32("seq")
	)

	if !hasC {
		// drop: missign "c"
		tracef("drop // no `c`")
		return
	}

	c := e.channels[cid]
	if c == nil {
		if !hasType {
			tracef("drop // no `type`")
			return // drop (missing typ)
		}

		h := e.endpoint.handlers[typ]
		if h == nil {
			tracef("drop // no handler for `%s`", typ)
			return // drop (no handler)
		}

		c = newChannel(e.hashname, typ, hasSeq, true, nil, nil, nil, nil)
		panic("fix this")
		c.id = cid
		err = e.register_channel(c)
		if err != nil {
			return // drop (register failed)
		}

		go h.ServeTelehash(c)
	}

	c.received_packet(pkt)
}

func (e *exchange) deliver_packet(op opExchangeWrite) {
	pkt, err := e.cipher.EncryptPacket(op.pkt)
	if err != nil {
		if op.cErr != nil {
			op.cErr <- err
		}
		return
	}

	addr := e.addressBook.ActiveAddress()

	err = e.endpoint.deliver(pkt, addr)
	if err != nil {
		if op.cErr != nil {
			op.cErr <- err
		}
		return
	}

	if op.cErr != nil {
		op.cErr <- nil
	}
	return
}

func (e *exchange) expire(err error) {
	tracef("expire(%p, %q)", e, err)
	e.state = expiredExchangeState

	// // cancel schedule
	// e.tExpire.Cancel()
	// e.tBreak.Cancel()
	// e.tDeliverHandshake.Cancel()

	// // unregister
	// delete(e.endpoint.hashnames, e.hashname)
	// delete(e.endpoint.tokens, e.token)

	// e.endpoint.subscribers.Emit(&ExchangeClosedEvent{e.hashname, err})
}

func (e *exchange) getNextSeq() uint32 {
	seq := e.next_seq
	if n := uint32(time.Now().Unix()); seq < n {
		seq = n
	}
	if seq < e.last_seq {
		seq = e.last_seq + 1
	}
	if seq == 0 {
		seq++
	}

	if e.cipher.IsHigh() {
		// must be odd
		if seq%2 == 0 {
			seq++
		}
	} else {
		// must be even
		if seq%2 == 1 {
			seq++
		}
	}

	e.next_seq = seq + 2
	return seq
}

func (e *exchange) reset_expire() {
	if len(e.channels) > 0 {
		e.tExpire.Stop()
	} else {
		e.tExpire.Reset(2 * 60 * time.Second)
	}
}

func (e *exchange) on_expire() {
	e.expire(nil)
}

func (e *exchange) reset_break() {
	e.tBreak.Reset(2 * 60 * time.Second)
}

func (e *exchange) on_break() {
	e.expire(BrokenExchange(e.hashname))
}

func (e *exchange) on_deliver_handshake() {
	e.deliver_handshake(0, nil)
}

func (x *exchange) register_channel(ch *Channel) error {
	if ch.id == 0 {
		ch.id = x.nextChannelId()
	}
	x.channels[ch.id] = ch
	x.reset_expire()
	return nil
}

func (x *exchange) unregister_channel(ch *Channel) {
	delete(x.channels, ch.id)
	x.reset_expire()
}

func (x *exchange) nextChannelId() uint32 {
	id := x.next_channel_id

	if id == 0 {
		// zero is not valid
		id++
	}

	if x.cipher.IsHigh() {
		// must be odd
		if id%2 == 0 {
			id++
		}
	} else {
		// must be even
		if id%2 == 1 {
			id++
		}
	}

	x.next_channel_id = id + 2
	return id
}
