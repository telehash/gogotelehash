package e3x

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/bufpool"
	"bitbucket.org/simonmenke/go-telehash/util/logs"
)

var ErrInvalidHandshake = errors.New("e3x: invalid handshake")

type BrokenExchangeError hashname.H

func (err BrokenExchangeError) Error() string {
	return "e3x: broken exchange " + string(err)
}

type ExchangeState uint8

const (
	ExchangeInitialising ExchangeState = 0

	ExchangeDialing ExchangeState = 1 << iota
	ExchangeIdle
	ExchangeActive
	ExchangeExpired
	ExchangeBroken
)

func (s ExchangeState) IsOpen() bool {
	return s&(ExchangeIdle|ExchangeActive) > 0
}

func (s ExchangeState) IsClosed() bool {
	return s&(ExchangeExpired|ExchangeBroken) > 0
}

func (s ExchangeState) String() string {
	switch s {
	case ExchangeInitialising:
		return "initialising"
	case ExchangeDialing:
		return "dialing"
	case ExchangeIdle:
		return "idle"
	case ExchangeActive:
		return "active"
	case ExchangeExpired:
		return "expired"
	case ExchangeBroken:
		return "broken"
	default:
		panic("invalid state")
	}
}

type Exchange struct {
	mtx      sync.Mutex
	cndState *sync.Cond

	state           ExchangeState
	last_local_seq  uint32
	last_remote_seq uint32
	next_seq        uint32
	token           cipherset.Token
	localIdent      *Ident
	remoteIdent     *Ident
	csid            uint8
	cipher          cipherset.State
	next_channel_id uint32
	channels        map[uint32]*channelEntry
	addressBook     *addressBook
	handlers        map[string]Handler
	err             error

	transportWriter transportWriter
	observers       Observers
	log             *logs.Logger

	nextHandshake     int
	tExpire           *time.Timer
	tBreak            *time.Timer
	tDeliverHandshake *time.Timer
}

type channelEntry struct {
	c *Channel
}

type transportWriter interface {
	WriteMessage([]byte, transports.Addr) error
}

func (x *Exchange) State() ExchangeState {
	x.mtx.Lock()
	s := x.state
	x.mtx.Unlock()
	return s
}

func (x *Exchange) String() string {
	return fmt.Sprintf("<Exchange %s state=%s>", x.remoteIdent.Hashname(), x.State())
}

func newExchange(
	localIdent *Ident,
	remoteIdent *Ident,
	handshake cipherset.Handshake,
	token cipherset.Token,
	transportWriter transportWriter,
	observers Observers,
	handlers map[string]Handler,
	log *logs.Logger,
) (*Exchange, error) {
	x := &Exchange{
		localIdent:      localIdent,
		remoteIdent:     remoteIdent,
		channels:        make(map[uint32]*channelEntry),
		transportWriter: transportWriter,
		observers:       observers,
		handlers:        handlers,
	}

	x.cndState = sync.NewCond(&x.mtx)

	x.tBreak = time.AfterFunc(2*60*time.Second, x.on_break)
	x.tExpire = time.AfterFunc(60*time.Second, x.on_expire)
	x.tDeliverHandshake = time.AfterFunc(60*time.Second, x.on_deliver_handshake)
	x.reset_expire()
	x.reschedule_handshake()

	if localIdent == nil {
		panic("missing local addr")
	}

	if remoteIdent != nil {
		x.log = log.To(remoteIdent.Hashname())

		csid := cipherset.SelectCSID(localIdent.keys, remoteIdent.keys)
		cipher, err := cipherset.NewState(csid, localIdent.keys[csid])
		if err != nil {
			return nil, err
		}

		err = cipher.SetRemoteKey(remoteIdent.keys[csid])
		if err != nil {
			return nil, err
		}

		x.addressBook = newAddressBook(x.log)
		x.cipher = cipher
		x.csid = csid

		for _, addr := range remoteIdent.addrs {
			x.addressBook.AddAddress(addr)
		}
	}

	if handshake != nil {
		csid := handshake.CSID()
		cipher, err := cipherset.NewState(csid, localIdent.keys[csid])
		if err != nil {
			return nil, err
		}

		ok := cipher.ApplyHandshake(handshake)
		if !ok {
			return nil, ErrInvalidHandshake
		}

		hn, err := hashname.FromKeyAndIntermediates(csid, handshake.PublicKey().Public(), handshake.Parts())
		if err != nil {
			hn = "xxxx"
		}

		x.log = log.To(hn)
		x.token = token
		x.cipher = cipher
		x.csid = csid
		x.addressBook = newAddressBook(x.log)
	}

	return x, nil
}

func (x *Exchange) dial() error {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if x.state == 0 {
		x.state = ExchangeDialing
		x.deliver_handshake(0, nil)
		x.reschedule_handshake()
	}

	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}

	if !x.state.IsOpen() {
		return BrokenExchangeError(x.remoteIdent.Hashname())
	}

	return nil
}

func (x *Exchange) RemoteHashname() hashname.H {
	x.mtx.Lock()
	hn := x.remoteIdent.Hashname()
	x.mtx.Unlock()
	return hn
}

func (x *Exchange) RemoteIdent() *Ident {
	x.mtx.Lock()
	ident := x.remoteIdent.withPaths(x.addressBook.KnownAddresses())
	x.mtx.Unlock()
	return ident
}

func (x *Exchange) ActivePath() transports.Addr {
	x.mtx.Lock()
	addr := x.addressBook.ActiveAddress()
	x.mtx.Unlock()
	return addr
}

func (x *Exchange) received(op opRead) {
	if len(op.msg) >= 3 && op.msg[1] == 1 {
		x.received_handshake(op)
	} else {
		x.received_packet(op)
	}

	bufpool.PutBuffer(op.msg)
}

func (x *Exchange) received_handshake(op opRead) bool {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	var (
		pkt       *lob.Packet
		handshake cipherset.Handshake
		csid      uint8
		seq       uint32
		err       error
	)

	if len(op.msg) < 3 {
		return false
	}

	pkt, err = lob.Decode(op.msg)
	if err != nil {
		tracef("handshake: invalid (%s)", err)
		return false
	}

	if len(pkt.Head) != 1 {
		tracef("handshake: invalid (%s)", "wrong header length")
		return false
	}
	csid = uint8(pkt.Head[0])

	handshake, err = cipherset.DecryptHandshake(csid, x.localIdent.keys[csid], pkt.Body)
	if err != nil {
		tracef("handshake: invalid (%s)", err)
		return false
	}
	// tracef("(id=%d) receiving_handshake(%p) seq=%v", x.addressBook.id, x, handshake.At())

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

	if x.remoteIdent == nil {
		ident, err := NewIdent(
			cipherset.Keys{x.csid: handshake.PublicKey()},
			handshake.Parts(),
			[]transports.Addr{op.src},
		)
		if err != nil {
			tracef("handshake: invalid (%s)", err)
			return false
		}
		x.remoteIdent = ident
		x.token = cipherset.ExtractToken(op.msg)
	}

	// tracef("(id=%d) seq=%d state=%v isLocalSeq=%v", x.addressBook.id, seq, x.state, x.isLocalSeq(seq))

	if x.isLocalSeq(seq) {
		x.reset_break()
		x.addressBook.ReceivedHandshake(op.src)
	} else {
		x.addressBook.AddAddress(op.src)
		x.deliver_handshake(seq, op.src)
	}

	if x.state == ExchangeDialing || x.state == ExchangeInitialising {
		// tracef("(id=%d) opened", x.addressBook.id)

		x.state = ExchangeIdle
		x.reset_expire()
		x.cndState.Broadcast()

		x.observers.Trigger(&ExchangeOpenedEvent{x})
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
	// tracef("(id=%d) delivering_handshake(%p, spray=%v, addr=%s)",
	// e.addressBook.id, e, addr == nil, addr)

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
	}

	pkt.Body, err = e.cipher.EncryptHandshake(seq, e.localIdent.parts)
	if err != nil {
		return err
	}

	pktData, err = lob.Encode(pkt)
	if err != nil {
		return err
	}

	e.last_local_seq = seq

	for _, addr := range addrs {
		err := e.transportWriter.WriteMessage(pktData, addr)
		if err == nil {
			e.addressBook.SentHandshake(addr)
		}
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
	// tracef("(id=%d) reschedule_handshake(%s)", e.addressBook.id, d)
	e.tDeliverHandshake.Reset(d)
}

func (x *Exchange) received_packet(op opRead) {
	pkt, err := lob.Decode(op.msg)
	if err != nil {
		return // drop
	}

	{
		x.mtx.Lock()
		if !x.state.IsOpen() {
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
				x.remoteIdent.Hashname(),
				typ,
				hasSeq,
				true,
				x,
			)
			c.id = cid

			entry = &channelEntry{c}

			x.channels[c.id] = entry
			x.reset_expire()

			x.observers.Trigger(&ChannelOpenedEvent{c})

			go h.ServeTelehash(c)
		}
		x.mtx.Unlock()
	}

	entry.c.received_packet(pkt)
}

func (x *Exchange) deliver_packet(pkt *lob.Packet) error {
	x.mtx.Lock()
	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}
	if !x.state.IsOpen() {
		return BrokenExchangeError(x.remoteIdent.Hashname())
	}
	addr := x.addressBook.ActiveAddress()
	x.mtx.Unlock()

	pkt, err := x.cipher.EncryptPacket(pkt)
	if err != nil {
		return err
	}

	msg, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	err = x.transportWriter.WriteMessage(msg, addr)

	bufpool.PutBuffer(pkt.Body)
	bufpool.PutBuffer(msg)

	return err
}

func (x *Exchange) expire(err error) {
	tracef("expire(%p, %q)", x, err)

	x.mtx.Lock()
	if err == nil {
		x.state = ExchangeExpired
	} else {
		if x.err != nil {
			x.err = err
		}
		x.state = ExchangeBroken
	}
	x.cndState.Broadcast()

	x.tBreak.Stop()
	x.tExpire.Stop()
	x.tDeliverHandshake.Stop()

	x.mtx.Unlock()

	for _, e := range x.channels {
		e.c.on_close_deadline_reached()
	}

	x.observers.Trigger(&ExchangeClosedEvent{x, err})
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
	if x == nil {
		return
	}
	x.expire(nil)
}

func (x *Exchange) on_break() {
	if x == nil {
		return
	}
	x.expire(BrokenExchangeError(x.remoteIdent.Hashname()))
}

func (x *Exchange) reset_expire() {
	active := len(x.channels) > 0

	if active {
		x.tExpire.Stop()
	} else {
		if x.state.IsOpen() {
			x.tExpire.Reset(2 * 60 * time.Second)
		}
	}

	if x.state.IsOpen() {
		old := x.state
		if active {
			x.state = ExchangeActive
		} else {
			x.state = ExchangeIdle
		}
		if x.state != old {
			x.cndState.Broadcast()
		}
	}
}

func (x *Exchange) reset_break() {
	x.tBreak.Reset(2 * 60 * time.Second)
}

func (x *Exchange) unregister_channel(channelId uint32) {
	x.mtx.Lock()

	entry := x.channels[channelId]
	if entry != nil {
		delete(x.channels, channelId)
		x.reset_expire()

		x.observers.Trigger(&ChannelClosedEvent{entry.c})
	}

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

func (x *Exchange) waitDone() {
	x.mtx.Lock()
	for x.state != ExchangeExpired && x.state != ExchangeBroken {
		x.cndState.Wait()
	}
	x.mtx.Unlock()
}

func (x *Exchange) Open(typ string, reliable bool) (*Channel, error) {
	var (
		c     *Channel
		entry *channelEntry
	)

	c = newChannel(
		x.remoteIdent.Hashname(),
		typ,
		reliable,
		false,
		x,
	)

	x.mtx.Lock()
	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}
	if !x.state.IsOpen() {
		x.mtx.Unlock()
		return nil, BrokenExchangeError(x.remoteIdent.Hashname())
	}

	c.id = x.nextChannelId()
	entry = &channelEntry{c}
	x.channels[c.id] = entry
	x.reset_expire()
	x.mtx.Unlock()

	x.observers.Trigger(&ChannelOpenedEvent{c})
	return c, nil
}

func (x *Exchange) SenderToken() cipherset.Token {
	return x.cipher.SenderToken()
}

func (x *Exchange) ReceiverToken() cipherset.Token {
	return x.cipher.ReceiverToken()
}

func (x *Exchange) AddPathCandidate(addr transports.Addr) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	x.addressBook.AddAddress(addr)
}
