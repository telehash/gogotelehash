package e3x

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/internal/util/tracer"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/transports"
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
	TID tracer.ID

	mtx      sync.Mutex
	cndState *sync.Cond

	state         ExchangeState
	lastLocalSeq  uint32
	lastRemoteSeq uint32
	nextSeq       uint32
	localIdent    *Identity
	remoteIdent   *Identity
	csid          uint8
	cipher        cipherset.State
	nextChannelID uint32
	channels      *channelSet
	addressBook   *addressBook
	err           error

	endpoint      endpointI
	listenerSet   *listenerSet
	log           *logs.Logger
	exchangeHooks ExchangeHooks
	channelHooks  ChannelHooks

	nextHandshake     int
	tExpire           *time.Timer
	tBreak            *time.Timer
	tDeliverHandshake *time.Timer
}

type ExchangeOption func(e *Exchange) error

type endpointI interface {
	getTID() tracer.ID
	getTransport() transports.Transport
}

func newExchange(
	localIdent *Identity, remoteIdent *Identity, handshake cipherset.Handshake,
	log *logs.Logger,
	options ...ExchangeOption,
) (*Exchange, error) {
	x := &Exchange{
		TID:         tracer.NewID(),
		localIdent:  localIdent,
		remoteIdent: remoteIdent,
		channels:    &channelSet{},
	}
	x.traceNew()

	x.cndState = sync.NewCond(&x.mtx)

	x.tBreak = time.AfterFunc(2*60*time.Second, x.onBreak)
	x.tExpire = time.AfterFunc(60*time.Second, x.onExpire)
	x.tDeliverHandshake = time.AfterFunc(60*time.Second, x.onDeliverHandshake)
	x.resetExpire()
	x.rescheduleHandshake()

	x.setOptions(options...)
	x.channelHooks.Register(ChannelHook{OnClosed: x.unregisterChannel})

	if localIdent == nil {
		panic("missing local addr")
	}

	if remoteIdent != nil {
		x.log = log.To(remoteIdent.Hashname())

		csid := cipherset.SelectCSID(localIdent.keys, remoteIdent.keys)
		cipher, err := cipherset.NewState(csid, localIdent.keys[csid])
		if err != nil {
			return nil, x.traceError(err)
		}

		err = cipher.SetRemoteKey(remoteIdent.keys[csid])
		if err != nil {
			return nil, x.traceError(err)
		}

		x.addressBook = newAddressBook(x.log)
		x.cipher = cipher
		x.csid = csid

		for _, addr := range remoteIdent.addrs {
			x.addressBook.AddPipe(newPipe(x.endpoint.getTransport(), nil, addr, x))
		}
	}

	if handshake != nil {
		csid := handshake.CSID()
		cipher, err := cipherset.NewState(csid, localIdent.keys[csid])
		if err != nil {
			return nil, x.traceError(err)
		}

		ok := cipher.ApplyHandshake(handshake)
		if !ok {
			return nil, x.traceError(ErrInvalidHandshake)
		}

		hn, err := hashname.FromKeyAndIntermediates(csid, handshake.PublicKey().Public(), handshake.Parts())
		if err != nil {
			x.traceError(err)
			hn = "xxxx"
		}

		x.log = log.To(hn)
		x.cipher = cipher
		x.csid = csid
		x.addressBook = newAddressBook(x.log)
	}

	return x, nil
}

func (x *Exchange) setOptions(options ...ExchangeOption) error {
	for _, option := range options {
		if err := option(x); err != nil {
			return err
		}
	}
	return nil
}

func registerEndpoint(e *Endpoint) ExchangeOption {
	return func(x *Exchange) error {
		x.endpoint = e
		x.listenerSet = e.listenerSet.Inherit()
		x.exchangeHooks = e.exchangeHooks
		x.channelHooks = e.channelHooks
		x.exchangeHooks.exchange = x
		x.channelHooks.exchange = x
		return nil
	}
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

func (x *Exchange) getTID() tracer.ID {
	return x.TID
}

func (x *Exchange) traceError(err error) error {
	if tracer.Enabled && err != nil {
		tracer.Emit("exchange.error", tracer.Info{
			"exchange_id": x.TID,
			"error":       err.Error(),
		})
	}
	return err
}

func (x *Exchange) traceNew() {
	if tracer.Enabled {
		tracer.Emit("exchange.new", tracer.Info{
			"exchange_id": x.TID,
			"endpoint_id": x.endpoint.getTID(),
		})
	}
}

func (x *Exchange) traceStarted() {
	if tracer.Enabled {
		tracer.Emit("exchange.started", tracer.Info{
			"exchange_id": x.TID,
			"peer":        x.remoteIdent.Hashname().String(),
		})
	}
}

func (x *Exchange) traceStopped() {
	if tracer.Enabled {
		tracer.Emit("exchange.stopped", tracer.Info{
			"exchange_id": x.TID,
		})
	}
}

func (x *Exchange) traceDroppedHandshake(msg message, handshake cipherset.Handshake, reason string) {
	if tracer.Enabled {
		info := tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"reason":      reason,
		}

		if handshake != nil {
			info["handshake"] = tracer.Info{
				"csid":       fmt.Sprintf("%x", handshake.CSID()),
				"parts":      handshake.Parts(),
				"at":         handshake.At(),
				"public_key": handshake.PublicKey().String(),
			}
		}

		tracer.Emit("exchange.drop.handshake", info)
	}
}

func (x *Exchange) traceReceivedHandshake(msg message, handshake cipherset.Handshake) {
	if tracer.Enabled {
		tracer.Emit("exchange.rcv.handshake", tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"handshake": tracer.Info{
				"csid":       fmt.Sprintf("%x", handshake.CSID()),
				"parts":      handshake.Parts(),
				"at":         handshake.At(),
				"public_key": handshake.PublicKey().String(),
			},
		})
	}
}

func (x *Exchange) traceDroppedPacket(msg message, pkt *lob.Packet, reason string) {
	if tracer.Enabled {
		info := tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"reason":      reason,
		}

		if pkt != nil {
			info["packet"] = tracer.Info{
				"header": pkt.Header(),
				"body":   base64.StdEncoding.EncodeToString(pkt.Body),
			}
		}

		tracer.Emit("exchange.rcv.packet", info)
	}
}

func (x *Exchange) traceReceivedPacket(msg message, pkt *lob.Packet) {
	if tracer.Enabled {
		tracer.Emit("exchange.rcv.packet", tracer.Info{
			"exchange_id": x.TID,
			"packet_id":   msg.TID,
			"packet": tracer.Info{
				"header": pkt.Header(),
				"body":   base64.StdEncoding.EncodeToString(pkt.Body),
			},
		})
	}
}

// Dial exchanges the initial handshakes. It will timeout after 2 minutes.
func (x *Exchange) Dial() error {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if x.state == 0 {
		x.state = ExchangeDialing
		x.deliverHandshake()
		x.rescheduleHandshake()
	}

	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}

	if !x.state.IsOpen() {
		return BrokenExchangeError(x.remoteIdent.Hashname())
	}

	return nil
}

// RemoteHashname returns the hashname of the remote peer.
func (x *Exchange) RemoteHashname() hashname.H {
	x.mtx.Lock()
	hn := x.remoteIdent.Hashname()
	x.mtx.Unlock()
	return hn
}

// RemoteIdentity returns the Identity of the remote peer.
func (x *Exchange) RemoteIdentity() *Identity {
	x.mtx.Lock()
	ident := x.remoteIdent.withPaths(x.addressBook.KnownAddresses())
	x.mtx.Unlock()
	return ident
}

// ActivePath returns the path that is currently used for channel packets.
func (x *Exchange) ActivePath() net.Addr {
	x.mtx.Lock()
	addr := x.addressBook.ActiveConnection().RemoteAddr()
	x.mtx.Unlock()
	return addr
}

// ActivePipe returns the pipe that is currently used for channel packets.
func (x *Exchange) ActivePipe() *Pipe {
	x.mtx.Lock()
	pipe := x.addressBook.ActiveConnection()
	x.mtx.Unlock()
	return pipe
}

// KnownPaths returns all the know addresses of the remote endpoint.
func (x *Exchange) KnownPaths() []net.Addr {
	x.mtx.Lock()
	addrs := x.addressBook.KnownAddresses()
	x.mtx.Unlock()
	return addrs
}

// KnownPipes returns all the know pipes of the remote endpoint.
func (x *Exchange) KnownPipes() []*Pipe {
	x.mtx.Lock()
	pipes := x.addressBook.KnownPipes()
	x.mtx.Unlock()
	return pipes
}

func (x *Exchange) received(msg message) {
	if msg.IsHandshake {
		x.receivedHandshake(msg)
	} else {
		x.receivedPacket(msg)
	}

	bufpool.PutBuffer(msg.Data)
}

func (x *Exchange) onDeliverHandshake() {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	x.rescheduleHandshake()
	x.deliverHandshake()
}

func (x *Exchange) deliverHandshake() error {
	var (
		pktData []byte
		err     error
	)

	x.addressBook.NextHandshakeEpoch()

	pktData, err = x.generateHandshake(0)
	if err != nil {
		return err
	}

	for _, pipe := range x.addressBook.HandshakePipes() {
		_, err := pipe.Write(pktData)
		if err == nil {
			x.addressBook.SentHandshake(pipe)
		}
	}

	return nil
}

func (x *Exchange) rescheduleHandshake() {
	if x.nextHandshake <= 0 {
		x.nextHandshake = 4
	} else {
		x.nextHandshake = x.nextHandshake * 2
	}

	if x.nextHandshake > 60 {
		x.nextHandshake = 60
	}

	if n := x.nextHandshake / 3; n > 0 {
		x.nextHandshake -= rand.Intn(n)
	}

	var d = time.Duration(x.nextHandshake) * time.Second
	x.tDeliverHandshake.Reset(d)
}

func (x *Exchange) receivedPacket(msg message) {
	const (
		dropInvalidPacket         = "invalid lob packet"
		dropExchangeIsNotOpen     = "exchange is not open"
		dropMissingChannelID      = "missing channel id header"
		dropMissingChannelType    = "missing channel type header"
		dropMissingChannelHandler = "missing channel handler"
	)

	{
		x.mtx.Lock()
		state := x.state
		x.mtx.Unlock()

		if !state.IsOpen() {
			x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
			x.traceDroppedPacket(msg, nil, dropExchangeIsNotOpen)
			return // drop
		}
	}

	pkt, err := lob.Decode(msg.Data)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, dropInvalidPacket)
		return // drop
	}

	pkt, err = x.cipher.DecryptPacket(pkt)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, err.Error())
		return // drop
	}
	pkt.TID = msg.TID
	var (
		hdr          = pkt.Header()
		cid, hasC    = hdr.C, hdr.HasC
		typ, hasType = hdr.Type, hdr.HasType
		hasSeq       = hdr.HasSeq
		c            *Channel
	)

	if !hasC {
		// drop: missing "c"
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedPacket(msg, pkt, dropMissingChannelID)
		return
	}

	{
		x.mtx.Lock()
		c = x.channels.Get(cid)
		if c == nil {
			if !hasType {
				x.mtx.Unlock()
				x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
				x.traceDroppedPacket(msg, pkt, dropMissingChannelType)
				return // drop (missing typ)
			}

			listener := x.listenerSet.Get(typ)
			if listener == nil {
				x.mtx.Unlock()
				x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
				x.traceDroppedPacket(msg, pkt, dropMissingChannelHandler)
				return // drop (no handler)
			}

			c = newChannel(
				x.remoteIdent.Hashname(),
				typ,
				hasSeq,
				true,
				x,
				registerExchange(x),
			)
			c.id = cid
			x.channels.Add(cid, c)
			x.resetExpire()

			x.mtx.Unlock()

			x.log.Printf("\x1B[32mOpened channel\x1B[0m %q %d", typ, cid)
			c.channelHooks.Opened()

			listener.handle(c)
		} else {
			x.mtx.Unlock()
		}
	}

	x.traceReceivedPacket(msg, pkt)
	c.receivedPacket(pkt)
}

func (x *Exchange) deliverPacket(pkt *lob.Packet, p *Pipe) error {
	x.mtx.Lock()
	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}
	if !x.state.IsOpen() {
		return BrokenExchangeError(x.remoteIdent.Hashname())
	}
	if p == nil {
		p = x.addressBook.ActiveConnection()
	}
	x.mtx.Unlock()

	pkt, err := x.cipher.EncryptPacket(pkt)
	if err != nil {
		return err
	}

	msg, err := lob.Encode(pkt)
	if err != nil {
		return err
	}

	_, err = p.Write(msg)

	bufpool.PutBuffer(pkt.Body)
	bufpool.PutBuffer(msg)

	return err
}

func (x *Exchange) expire(err error) {
	x.mtx.Lock()
	if x.state == ExchangeExpired || x.state == ExchangeBroken {
		x.mtx.Unlock()
		return
	}

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

	for _, c := range x.channels.All() {
		c.onCloseDeadlineReached()
	}

	x.traceStopped()
	x.exchangeHooks.Closed(err)
}

func (x *Exchange) getNextSeq() uint32 {
	seq := x.nextSeq
	if n := uint32(time.Now().Unix()); seq < n {
		seq = n
	}
	if seq < x.lastLocalSeq {
		seq = x.lastLocalSeq + 1
	}
	if seq < x.lastRemoteSeq {
		seq = x.lastRemoteSeq + 1
	}
	if seq == 0 {
		seq++
	}

	if x.cipher.IsHigh() {
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

	x.nextSeq = seq + 2
	return seq
}

func (x *Exchange) isLocalSeq(seq uint32) bool {
	if x.cipher.IsHigh() {
		// must be odd
		return seq%2 == 1
	}
	// must be even
	return seq%2 == 0
}

func (x *Exchange) onExpire() {
	if x == nil {
		return
	}
	x.expire(nil)
}

func (x *Exchange) onBreak() {
	if x == nil {
		return
	}
	x.expire(BrokenExchangeError(x.remoteIdent.Hashname()))
}

func (x *Exchange) resetExpire() {
	active := !x.channels.Idle()

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

func (x *Exchange) resetBreak() {
	x.tBreak.Reset(2 * 60 * time.Second)
}

func (x *Exchange) unregisterChannel(_ *Endpoint, _ *Exchange, c *Channel) error {
	if x.channels.Remove(c.id) {
		x.mtx.Lock()
		x.resetExpire()
		x.mtx.Unlock()

		x.log.Printf("\x1B[31mClosed channel\x1B[0m %q %d", c.typ, c.id)
	}

	return nil
}

func (x *Exchange) getNextChannelID() uint32 {
	id := x.nextChannelID

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

	x.nextChannelID = id + 2
	return id
}

func (x *Exchange) waitDone() {
	x.mtx.Lock()
	for x.state != ExchangeExpired && x.state != ExchangeBroken {
		x.cndState.Wait()
	}
	x.mtx.Unlock()
}

// Open a channel.
func (x *Exchange) Open(typ string, reliable bool) (*Channel, error) {
	var (
		c *Channel
	)

	c = newChannel(
		x.remoteIdent.Hashname(),
		typ,
		reliable,
		false,
		x,
		registerExchange(x),
	)

	x.mtx.Lock()
	for x.state == ExchangeDialing {
		x.cndState.Wait()
	}
	if !x.state.IsOpen() {
		x.mtx.Unlock()
		return nil, BrokenExchangeError(x.remoteIdent.Hashname())
	}

	c.id = x.getNextChannelID()
	x.channels.Add(c.id, c)
	x.resetExpire()
	x.mtx.Unlock()

	x.log.Printf("\x1B[32mOpened channel\x1B[0m %q %d", typ, c.id)
	c.channelHooks.Opened()
	return c, nil
}

// LocalToken returns the token identifying the local side of the exchange.
func (x *Exchange) LocalToken() cipherset.Token {
	return x.cipher.LocalToken()
}

// RemoteToken returns the token identifying the remote side of the exchange.
func (x *Exchange) RemoteToken() cipherset.Token {
	return x.cipher.RemoteToken()
}

// AddPathCandidate adds a new path tto the exchange. The path is
// only used when it performs better than any other paths.
func (x *Exchange) AddPathCandidate(addr net.Addr) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if x.addressBook.PipeToAddr(addr) == nil {
		p := newPipe(x.endpoint.getTransport(), nil, addr, x)
		x.addressBook.AddPipe(p)
	}
}

// GenerateHandshake can be used to generate a new handshake packet.
// This is useful when the exchange doesn't know where to send the handshakes yet.
func (x *Exchange) GenerateHandshake() ([]byte, error) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	return x.generateHandshake(0)
}

func (x *Exchange) generateHandshake(seq uint32) ([]byte, error) {
	var (
		pkt     = &lob.Packet{Head: []byte{x.csid}}
		pktData []byte
		err     error
	)

	if seq == 0 {
		seq = x.getNextSeq()
	}

	pkt.Body, err = x.cipher.EncryptHandshake(seq, x.localIdent.parts)
	if err != nil {
		return nil, err
	}

	pktData, err = lob.Encode(pkt)
	if err != nil {
		return nil, err
	}

	if x.lastLocalSeq < seq {
		x.lastLocalSeq = seq
	}

	return pktData, nil
}

// ApplyHandshake applies a (out-of-band) handshake to the exchange. When the
// handshake is accepted err is nil. When the handshake is a request-handshake
// and it is accepted response will contain a response-handshake packet.
func (x *Exchange) ApplyHandshake(handshake cipherset.Handshake, src net.Addr) (response []byte, ok bool) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	p := x.addressBook.PipeToAddr(src)
	if p == nil {
		p = newPipe(x.endpoint.getTransport(), nil, src, x)
		x.addressBook.AddPipe(p)
	}

	return x.applyHandshake(handshake, p)
}

func (x *Exchange) applyHandshake(handshake cipherset.Handshake, pipe *Pipe) (response []byte, ok bool) {
	var (
		seq uint32
		err error
	)

	if handshake == nil {
		return nil, false
	}

	seq = handshake.At()
	if seq < x.lastRemoteSeq {
		// drop; a newer packet has already been processed
		return nil, false
	}

	if handshake.CSID() != x.csid {
		// drop; wrong csid
		return nil, false
	}

	if !x.cipher.ApplyHandshake(handshake) {
		// drop; handshake was rejected by the cipherset
		return nil, false
	}

	if x.remoteIdent == nil {
		ident, err := NewIdentity(
			cipherset.Keys{handshake.CSID(): handshake.PublicKey()},
			handshake.Parts(),
			nil,
		)
		if err != nil {
			// drop; invalid identity
			return nil, false
		}
		x.remoteIdent = ident
	}

	if x.isLocalSeq(seq) {
		x.resetBreak()
		x.addressBook.ReceivedHandshake(pipe)

	} else {
		x.addressBook.AddPipe(pipe)

		response, err = x.generateHandshake(seq)
		if err != nil {
			// drop; invalid identity
			return nil, false
		}
	}

	if x.state == ExchangeDialing || x.state == ExchangeInitialising {
		x.traceStarted()

		x.state = ExchangeIdle
		x.resetExpire()
		x.cndState.Broadcast()

		go x.exchangeHooks.Opened()
	}

	return response, true
}

func (x *Exchange) receivedHandshake(msg message) bool {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	var (
		pkt       *lob.Packet
		handshake cipherset.Handshake
		csid      uint8
		err       error
	)

	if !msg.IsHandshake {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedHandshake(msg, nil, "invalid packet")
		return false
	}

	pkt, err = lob.Decode(msg.Data)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, err)
		x.traceDroppedHandshake(msg, nil, err.Error())
		return false
	}

	if len(pkt.Head) != 1 {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedHandshake(msg, nil, "invalid header")
		return false
	}
	csid = uint8(pkt.Head[0])

	handshake, err = cipherset.DecryptHandshake(csid, x.localIdent.keys[csid], pkt.Body)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, err)
		x.traceDroppedHandshake(msg, nil, err.Error())
		return false
	}

	resp, ok := x.applyHandshake(handshake, msg.Pipe)
	if !ok {
		x.exchangeHooks.DropPacket(msg.Data, msg.Pipe, nil)
		x.traceDroppedHandshake(msg, handshake, "failed to apply")
		return false
	}

	x.lastRemoteSeq = handshake.At()

	if resp != nil {
		msg.Pipe.Write(resp)
	}

	x.traceReceivedHandshake(msg, handshake)
	return true
}
