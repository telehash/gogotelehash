package e3x

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var ErrInvalidHandshake = errors.New("e3x: invalid handshake")

type BrokenExchangeError hashname.H

func (err BrokenExchangeError) Error() string {
	return "e3x: broken exchange " + string(err)
}

type exchangeState uint8

const (
	dialingExchangeState exchangeState = iota
	openedExchangeState
	expiredExchangeState
)

type Exchange struct {
	mtx     sync.Mutex
	cndOpen *sync.Cond

	state           exchangeState
	last_local_seq  uint32
	last_remote_seq uint32
	next_seq        uint32
	token           cipherset.Token
	localAddr       *Addr
	remoteAddr      *Addr
	csid            uint8
	cipher          cipherset.State
	next_channel_id uint32
	channels        map[uint32]*channelEntry
	addressBook     *addressBook
	handlers        map[string]Handler

	// owned channels
	cExchangeRead        chan opExchangeRead
	cExchangeMakeChannel chan *opExchangeMakeChannel
	cDone                chan struct{}
	cTerminate           chan struct{}

	// lended channels
	cTransportWrite   chan<- transports.WriteOp
	cDownstreamEvents chan<- events.E // exchange -> endpoint

	nextHandshake     int
	tExpire           *time.Timer
	tBreak            *time.Timer
	tDeliverHandshake *time.Timer
	subscribers       events.Hub
}

type opExchangeRead struct {
	pkt *lob.Packet
	err error
}

type opExchangeMakeChannel struct {
	typ      string
	reliable bool
	c        *Channel
	cErr     chan error
}

type opHandshakeRead struct {
	handshake cipherset.Handshake
	src       transports.Addr
}

type channelEntry struct {
	c *Channel
}

func newExchange(
	localAddr *Addr,
	remoteAddr *Addr,
	handshake cipherset.Handshake,
	token cipherset.Token,
	w chan<- transports.WriteOp,
	eDown chan<- events.E,
	handlers map[string]Handler,
) (*Exchange, error) {
	x := &Exchange{
		localAddr:            localAddr,
		remoteAddr:           remoteAddr,
		channels:             make(map[uint32]*channelEntry),
		addressBook:          newAddressBook(),
		cExchangeRead:        make(chan opExchangeRead),
		cExchangeMakeChannel: make(chan *opExchangeMakeChannel),
		cDone:                make(chan struct{}),
		cTerminate:           make(chan struct{}),
		cTransportWrite:      w,
		cDownstreamEvents:    eDown,
		handlers:             handlers,
	}

	x.cndOpen = sync.NewCond(&x.mtx)

	x.tBreak = time.AfterFunc(2*60*time.Second, x.on_break)
	x.tExpire = time.AfterFunc(60*time.Second, x.on_expire)
	x.tDeliverHandshake = time.AfterFunc(60*time.Second, x.on_deliver_handshake)
	x.reset_expire()
	x.reschedule_handshake()

	if localAddr == nil {
		panic("missing local addr")
	}

	if remoteAddr != nil {
		csid := cipherset.SelectCSID(localAddr.keys, remoteAddr.keys)
		cipher, err := cipherset.NewState(csid, localAddr.keys[csid])
		if err != nil {
			return nil, err
		}

		err = cipher.SetRemoteKey(remoteAddr.keys[csid])
		if err != nil {
			return nil, err
		}

		x.cipher = cipher
		x.csid = csid

		for _, addr := range remoteAddr.addrs {
			x.addressBook.AddAddress(addr)
		}
	}

	if handshake != nil {
		csid := handshake.CSID()
		cipher, err := cipherset.NewState(csid, localAddr.keys[csid])
		if err != nil {
			return nil, err
		}

		ok := cipher.ApplyHandshake(handshake)
		if !ok {
			return nil, ErrInvalidHandshake
		}

		x.token = token
		x.cipher = cipher
		x.csid = csid
	}

	return x, nil
}

func (x *Exchange) dial() error {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if x.state == openedExchangeState {
		return nil
	}

	x.deliver_handshake(0, nil)
	x.reschedule_handshake()

	for x.state == dialingExchangeState {
		x.cndOpen.Wait()
	}

	if x.state == expiredExchangeState {
		return BrokenExchangeError(x.remoteAddr.Hashname())
	}

	return nil
}

func (x *Exchange) terminate() {
	select {
	case <-x.cDone:
	case x.cTerminate <- struct{}{}:
	}
	<-x.cDone
}

func (x *Exchange) run() {
	if x == nil {
		return
	}

	defer func() {
		close(x.cDone)
		close(x.cExchangeMakeChannel)
	}()

	if len(x.addressBook.HandshakeAddresses()) > 0 {
	} else {
		// x.reschedule_handshake()
	}

	for {
		var (
			cExchangeMakeChannel = x.cExchangeMakeChannel
		)

		if x.state != openedExchangeState {
			// block until the exchange is opened
			cExchangeMakeChannel = nil
		}

		select {

		case op := <-cExchangeMakeChannel:
			x.open_channel(op)

		case <-x.cTerminate:
			x.on_expire()

		}

		if x.state == expiredExchangeState {
			return
		}
	}
}

func (e *Exchange) knownKeys() cipherset.Keys {
	return e.remoteAddr.keys
}

func (e *Exchange) knownParts() cipherset.Parts {
	return e.remoteAddr.parts
}

func (x *Exchange) received(op transports.ReadOp) {
	if len(op.Msg) >= 3 && op.Msg[1] == 1 {
		x.received_handshake(op)
	} else {
		x.received_packet(op)
	}
}

func (x *Exchange) received_handshake(op transports.ReadOp) bool {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	var (
		pkt       *lob.Packet
		handshake cipherset.Handshake
		csid      uint8
		seq       uint32
		err       error
	)

	if len(op.Msg) < 3 {
		return false
	}

	pkt, err = lob.Decode(op.Msg)
	if err != nil {
		tracef("handshake: invalid (%s)", err)
		return false
	}

	if len(pkt.Head) != 1 {
		tracef("handshake: invalid (%s)", "wronf header length")
		return false
	}
	csid = uint8(pkt.Head[0])

	handshake, err = cipherset.DecryptHandshake(csid, x.localAddr.keys[csid], pkt.Body)
	if err != nil {
		tracef("handshake: invalid (%s)", err)
		return false
	}
	tracef("(id=%d) receiving_handshake(%p) seq=%v", x.addressBook.id, x, handshake.At())

	seq = handshake.At()
	if seq < x.last_remote_seq {
		tracef("handshake: invalid (%s)", "seq already seen")
		return false
	}

	if csid != x.csid {
		tracef("handshake: invalid (%s)", "wrong csid")
		return false
	}

	if !x.cipher.ApplyHandshake(handshake) {
		tracef("handshake: invalid (%s)", "wrong handshake")
		return false
	}

	if x.remoteAddr == nil {
		addr, err := NewAddr(
			cipherset.Keys{x.csid: handshake.PublicKey()},
			handshake.Parts(),
			[]transports.Addr{op.Src},
		)
		if err != nil {
			tracef("handshake: invalid (%s)", err)
			return false
		}
		x.remoteAddr = addr
		x.token = cipherset.ExtractToken(op.Msg)
	}

	tracef("(id=%d) seq=%d state=%v isLocalSeq=%v", x.addressBook.id, seq, x.state, x.isLocalSeq(seq))

	if x.isLocalSeq(seq) {
		x.reset_break()
		x.addressBook.ReceivedHandshake(op.Src)
	} else {
		x.addressBook.AddAddress(op.Src)
		x.deliver_handshake(seq, op.Src)
	}

	if x.state == dialingExchangeState {
		tracef("(id=%d) opened", x.addressBook.id)
		x.state = openedExchangeState

		x.reset_expire()
		x.cndOpen.Broadcast()

		go func() {
			evt := &ExchangeOpenedEvent{x.remoteAddr.Hashname()}
			x.cDownstreamEvents <- evt
		}()
	}

	return true
}

func (x *Exchange) on_deliver_handshake() {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	x.reschedule_handshake()
	x.deliver_handshake(0, nil)
}

func (e *Exchange) deliver_handshake(seq uint32, addr transports.Addr) error {
	tracef("(id=%d) delivering_handshake(%p, spray=%v, addr=%s)",
		e.addressBook.id, e, addr == nil, addr)

	var (
		pkt     = &lob.Packet{Head: []byte{e.csid}}
		pktData []byte
		addrs   []transports.Addr
		err     error
	)

	if seq == 0 {
		seq = e.getNextSeq()
	}

	if addr != nil {
		addrs = append(addrs, addr)
	} else {
		e.addressBook.NextHandshakeEpoch()
		addrs = e.addressBook.HandshakeAddresses()
		if len(addrs) == 0 {
			e.on_break()
			return nil
		}
	}

	pkt.Body, err = e.cipher.EncryptHandshake(seq, e.localAddr.parts)
	if err != nil {
		return err
	}

	pktData, err = lob.Encode(pkt)
	if err != nil {
		return err
	}

	e.last_local_seq = seq

	cErr := make(chan error, len(addrs))
	for _, addr := range addrs {
		func() {
			defer func() { recover() }()
			e.cTransportWrite <- transports.WriteOp{pktData, addr, cErr}
			e.addressBook.SentHandshake(addr)
		}()
	}

	return nil
}

func (e *Exchange) reschedule_handshake() {
	if e.nextHandshake <= 0 {
		e.nextHandshake = 4
	} else {
		e.nextHandshake = e.nextHandshake * 2
	}

	if e.nextHandshake > 60 {
		e.nextHandshake = 60
	}

	if n := e.nextHandshake / 3; n > 0 {
		e.nextHandshake -= rand.Intn(n)
	}

	var d = time.Duration(e.nextHandshake) * time.Second
	tracef("(id=%d) reschedule_handshake(%s)", e.addressBook.id, d)
	e.tDeliverHandshake.Reset(d)
}

func (x *Exchange) received_packet(op transports.ReadOp) {
	pkt, err := lob.Decode(op.Msg)
	if err != nil {
		return // drop
	}

	{
		x.mtx.Lock()
		if x.state != openedExchangeState {
			tracef("drop // exchange not opened")
			return // drop
		}
		x.mtx.Unlock()
	}

	pkt, err = x.cipher.DecryptPacket(pkt)
	if err != nil {
		return // drop
	}
	var (
		cid, hasC    = pkt.Header().GetUint32("c")
		typ, hasType = pkt.Header().GetString("type")
		_, hasSeq    = pkt.Header().GetUint32("seq")
		c            *Channel
		entry        *channelEntry
	)

	if !hasC {
		// drop: missign "c"
		tracef("drop // no `c`")
		return
	}

	{
		x.mtx.Lock()
		entry = x.channels[cid]
		if entry == nil {
			if !hasType {
				tracef("drop // no `type`")
				x.mtx.Unlock()
				return // drop (missing typ)
			}

			h := x.handlers[typ]
			if h == nil {
				tracef("drop // no handler for `%s`", typ)
				x.mtx.Unlock()
				return // drop (no handler)
			}

			c = newChannel(
				x.remoteAddr.Hashname(),
				typ,
				hasSeq,
				true,
				x,
			)
			c.id = cid

			entry = &channelEntry{c}

			x.channels[c.id] = entry
			x.reset_expire()
			x.subscribers.Emit(&ChannelOpenedEvent{c})

			go h.ServeTelehash(c)
		}
		x.mtx.Unlock()
	}

	entry.c.received_packet(pkt)
}

func (e *Exchange) deliver_packet(pkt *lob.Packet) error {
	e.mtx.Lock()
	addr := e.addressBook.ActiveAddress()
	e.mtx.Unlock()

	pkt, err := e.cipher.EncryptPacket(pkt)
	if err != nil {
		return err
	}

	msg, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	cErr := make(chan error, 1)

	select {
	case e.cTransportWrite <- transports.WriteOp{Msg: msg, Dst: addr, C: cErr}:
		return <-cErr
	case <-e.cDone:
		return transports.ErrClosed
	}
}

func (x *Exchange) expire(err error) {
	tracef("expire(%p, %q)", x, err)

	x.mtx.Lock()
	x.state = expiredExchangeState
	x.cndOpen.Broadcast()

	x.tBreak.Stop()
	x.tExpire.Stop()
	x.tDeliverHandshake.Stop()

	x.mtx.Unlock()

	go func() {
		evt := &ExchangeClosedEvent{x.remoteAddr.Hashname(), err}
		x.cDownstreamEvents <- evt
	}()
}

func (e *Exchange) getNextSeq() uint32 {
	seq := e.next_seq
	if n := uint32(time.Now().Unix()); seq < n {
		seq = n
	}
	if seq < e.last_local_seq {
		seq = e.last_local_seq + 1
	}
	if seq < e.last_remote_seq {
		seq = e.last_remote_seq + 1
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

func (x *Exchange) isLocalSeq(seq uint32) bool {
	if x.cipher.IsHigh() {
		// must be odd
		return seq%2 == 1
	} else {
		// must be even
		return seq%2 == 0
	}
}

func (x *Exchange) on_expire() {
	x.expire(nil)
}

func (x *Exchange) on_break() {
	x.expire(BrokenExchangeError(x.remoteAddr.Hashname()))
}

func (x *Exchange) reset_expire() {
	if len(x.channels) > 0 {
		x.tExpire.Stop()
	} else {
		x.tExpire.Reset(2 * 60 * time.Second)
	}
}

func (x *Exchange) reset_break() {
	x.tBreak.Reset(2 * 60 * time.Second)
}

func (x *Exchange) unregister_channel(channelId uint32) {
	x.mtx.Lock()
	delete(x.channels, channelId)
	x.reset_expire()
	x.mtx.Unlock()
}

func (x *Exchange) nextChannelId() uint32 {
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

func (x *Exchange) done() <-chan struct{} {
	if x == nil {
		c := make(chan struct{})
		close(c)
		return c
	}
	return x.cDone
}

func (x *Exchange) Open(typ string, reliable bool) (*Channel, error) {
	op := opExchangeMakeChannel{typ, reliable, nil, make(chan error)}

	select {
	case x.cExchangeMakeChannel <- &op:
		// continue
	case <-x.cDone:
		return nil, BrokenExchangeError(x.remoteAddr.Hashname())
	}

	select {
	case err := <-op.cErr:
		if err != nil {
			return nil, err
		} else {
			return op.c, nil
		}
	case <-x.cDone:
		return nil, BrokenExchangeError(x.remoteAddr.Hashname())
	}
}

func (x *Exchange) open_channel(op *opExchangeMakeChannel) {
	var (
		c     *Channel
		entry *channelEntry
	)

	c = newChannel(
		x.remoteAddr.Hashname(),
		op.typ,
		op.reliable,
		false,
		x,
	)

	c.id = x.nextChannelId()
	entry = &channelEntry{c}
	x.channels[c.id] = entry
	x.reset_expire()
	x.subscribers.Emit(&ChannelOpenedEvent{c})

	op.c = c
	op.cErr <- nil
}

func (x *Exchange) Subscribe(c chan<- events.E) {
	x.subscribers.Subscribe(c)
}

func (x *Exchange) Unsubscribe(c chan<- events.E) {
	x.subscribers.Unubscribe(c)
}
