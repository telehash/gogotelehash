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
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/internal/util/logs"
	"github.com/telehash/gogotelehash/internal/util/tracer"
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
	lastLocalAt   uint32
	lastRemoteAt  uint32
	nextAt        uint32
	localIdent    *Identity
	remoteIdent   *Identity
	selfCipher    *cipherset.Self
	sessCipher    *cipherset.Session
	nextChannelID uint32
	channels      *channelSet
	addressBook   *addressBook
	err           error

	endpoint      endpointI
	listenerSet   *listenerSet
	exchangeSet   *exchangeSet
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
	localIdent *Identity,
	remoteIdent *Identity,
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

	if remoteIdent == nil {
		return nil, ErrUnidentifiable
	}

	x.log = log.To(remoteIdent.Hashname())
	for _, addr := range remoteIdent.addrs {
		x.addressBook.AddPipe(newPipe(x.endpoint.getTransport(), nil, addr, x))
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
		x.selfCipher = e.cipher
		x.listenerSet = e.listenerSet.Inherit()
		x.exchangeSet = e.exchangeSet
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
				"body":   base64.StdEncoding.EncodeToString(pkt.Body(nil)),
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
				"body":   base64.StdEncoding.EncodeToString(pkt.Body(nil)),
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
	hn := x.remoteIdent.Hashname()
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
	return x.addressBook.ActiveConnection().RemoteAddr()
}

// ActivePipe returns the pipe that is currently used for channel packets.
func (x *Exchange) ActivePipe() *Pipe {
	return x.addressBook.ActiveConnection()
}

// KnownPaths returns all the know addresses of the remote endpoint.
func (x *Exchange) KnownPaths() []net.Addr {
	return x.addressBook.KnownAddresses()
}

// KnownPipes returns all the know pipes of the remote endpoint.
func (x *Exchange) KnownPipes() []*Pipe {
	return x.addressBook.KnownPipes()
}

func (x *Exchange) dialDialerAddr(addr dialerAddr) (net.Conn, error) {
	return addr.Dial(x.endpoint.(*Endpoint), x)
}

func (x *Exchange) received(msg message) {
	if msg.IsHandshake {
		x.receivedHandshake(msg)
	} else {
		x.receivedPacket(msg)
	}

	msg.Data.Free()
}

func (x *Exchange) onDeliverHandshake() {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	x.rescheduleHandshake()
	x.deliverHandshake()
}

func (x *Exchange) deliverHandshake() error {
	var (
		pktData *bufpool.Buffer
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
		dropNoSession             = "exchange has no crypto session"
		dropMissingChannelID      = "missing channel id header"
		dropMissingChannelType    = "missing channel type header"
		dropMissingChannelHandler = "missing channel handler"
	)

	x.mtx.Lock()
	state := x.state
	cipher := x.sessCipher
	x.mtx.Unlock()

	if !state.IsOpen() {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, dropExchangeIsNotOpen)
		return // drop
	}
	if cipher == nil {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, dropNoSession)
		return // drop
	}

	pkt, err := lob.Decode(msg.Data)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, dropInvalidPacket)
		return // drop
	}

	pkt2, err := cipher.DecryptPacket(pkt)
	pkt.Free()
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedPacket(msg, nil, err.Error())
		return // drop
	}
	pkt2.TID = msg.TID
	var (
		hdr          = pkt2.Header()
		cid, hasC    = hdr.C, hdr.HasC
		typ, hasType = hdr.Type, hdr.HasType
		hasSeq       = hdr.HasSeq
		c            *Channel
	)

	if !hasC {
		// drop: missing "c"
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedPacket(msg, pkt2, dropMissingChannelID)
		return
	}

	{
		var addPromise *channelSetAddPromise
		c, addPromise = x.channels.GetOrAdd(cid)
		if c == nil {
			if !hasType {
				addPromise.Cancel()
				x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
				x.traceDroppedPacket(msg, pkt2, dropMissingChannelType)
				return // drop (missing typ)
			}

			listener := x.listenerSet.Get(typ)
			if listener == nil {
				addPromise.Cancel()
				x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
				x.traceDroppedPacket(msg, pkt2, dropMissingChannelHandler)
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
			addPromise.Add(c)

			x.mtx.Lock()
			x.resetExpire()
			x.mtx.Unlock()

			x.log.Printf("\x1B[32mOpened channel\x1B[0m %q %d", typ, cid)
			c.channelHooks.Opened()

			listener.handle(c)
		}
	}

	x.traceReceivedPacket(msg, pkt2)
	c.receivedPacket(pkt2)
}

func (x *Exchange) deliverPacket(pkt *lob.Packet, p *Pipe) error {
	x.mtx.Lock()
	for x.state == ExchangeDialing || x.sessCipher == nil {
		x.cndState.Wait()
	}
	if !x.state.IsOpen() {
		return BrokenExchangeError(x.remoteIdent.Hashname())
	}
	cipher := x.sessCipher
	x.mtx.Unlock()

	if p == nil {
		p = x.addressBook.ActiveConnection()
	}

	pkt2, err := cipher.EncryptPacket(pkt)
	if err != nil {
		return err
	}

	msg, err := lob.Encode(pkt2)
	pkt2.Free()
	if err != nil {
		return err
	}

	_, err = p.Write(msg)
	msg.Free()

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

	for _, p := range x.addressBook.KnownPipes() {
		p.Close()
	}

	x.exchangeSet.Remove(x)
	x.traceStopped()
	x.exchangeHooks.Closed(err)
}

func (x *Exchange) getNextAt() uint32 {
	at := x.nextAt
	if n := uint32(time.Now().Unix()); at < n {
		at = n
	}
	if at < x.lastLocalAt {
		at = x.lastLocalAt + 1
	}
	if at < x.lastRemoteAt {
		at = x.lastRemoteAt + 1
	}
	if at == 0 {
		at++
	}

	if x.sessCipher.IsHigh() {
		// must be odd
		if at%2 == 0 {
			at++
		}
	} else {
		// must be even
		if at%2 == 1 {
			at++
		}
	}

	x.nextAt = at + 2
	return at
}

func (x *Exchange) isLocalSeq(seq uint32) bool {
	if x.sessCipher.IsHigh() {
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

	if x.sessCipher.IsHigh() {
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
	return x.sessCipher.LocalToken()
}

// RemoteToken returns the token identifying the remote side of the exchange.
func (x *Exchange) RemoteToken() cipherset.Token {
	return x.sessCipher.RemoteToken()
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
func (x *Exchange) GenerateHandshake() (*bufpool.Buffer, error) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	return x.generateHandshake(0)
}

func (x *Exchange) generateHandshake(at uint32) (*bufpool.Buffer, error) {
	var (
		inner   *lob.Packet
		outer   *lob.Packet
		pktData *bufpool.Buffer
		err     error
	)

	if at == 0 {
		at = x.getNextAt()
	}

	inner, err = encodeHandshake(&cipherset.KeyHandshake{
		CSID:  x.sessCipher.CSID(),
		Key:   x.selfCipher.PublicKeys()[x.sessCipher.CSID()],
		Parts: x.localIdent.parts,
	})
	if err != nil {
		return nil, err
	}
	hdr := inner.Header()
	hdr.At, hdr.HasAt = at, true

	outer, err = x.sessCipher.EncryptMessage(inner)
	if err != nil {
		inner.Free()
		return nil, err
	}

	pktData, err = lob.Encode(outer)
	if err != nil {
		inner.Free()
		outer.Free()
		return nil, err
	}

	if x.lastLocalAt < at {
		x.lastLocalAt = at
	}

	inner.Free()
	outer.Free()

	return pktData, nil
}

func (x *Exchange) AddPipeConnection(conn net.Conn, addr net.Addr) (p *Pipe, added bool) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	if addr == nil {
		addr = conn.RemoteAddr()
	}

	p = x.addressBook.PipeToAddr(addr)
	if p == nil {
		p = newPipe(x.endpoint.getTransport(), conn, nil, x)
		x.addressBook.AddPipe(p)
		added = true
	}

	return p, added
}

// ApplyHandshake applies a (out-of-band) handshake to the exchange. When the
// handshake is accepted err is nil. When the handshake is a request-handshake
// and it is accepted response will contain a response-handshake packet.
func (x *Exchange) ApplyHandshake(handshake *lob.Packet, pipe *Pipe) (response *bufpool.Buffer, ok bool) {
	x.mtx.Lock()
	defer x.mtx.Unlock()

	return x.applyHandshake(handshake, pipe)
}

func (x *Exchange) applyHandshake(outer *lob.Packet, pipe *Pipe) (response *bufpool.Buffer, ok bool) {
	var (
		inner     *lob.Packet
		handshake Handshake
		ident     *Identity
		at        uint32
		err       error
	)

	if outer == nil {
		return nil, false
	}

	if x.sessCipher != nil {
		err = x.sessCipher.VerifyMessage(outer)
		if err == cipherset.ErrSessionReset {
			x.sessCipher = nil
			err = nil
		}
		if err != nil {
			return nil, false
		}
	}

	inner, err = x.selfCipher.DecryptMessage(outer)
	if err != nil {
		// drop; invalid packet
		return nil, false
	}

	at = inner.Header().At
	if !inner.Header().HasAt || at < x.lastRemoteAt {
		// drop; a newer packet has already been processed
		return nil, false
	}

	handshake, err = decodeHandshake(inner)
	if handshake == nil || err != nil {
		return nil, false
	}

	if key, ok := handshake.(*cipherset.KeyHandshake); ok {

		if x.sessCipher != nil && key.CSID != x.sessCipher.CSID() {
			// drop; wrong csid
			return nil, false
		}

		if x.remoteIdent != nil && x.remoteIdent.Hashname() != key.Hashname {
			// drop; invalid hashname
			return nil, false
		}

		if x.sessCipher == nil {
			sess, err := x.selfCipher.NewSession(map[uint8][]byte{key.CSID: key.Key})
			if err != nil {
				// drop; unable to create session
				return nil, false
			}

			err = sess.VerifyMessage(outer)
			if err != nil {
				// drop; invalid handshake
				return nil, false
			}

			x.sessCipher = sess
		}

		if x.remoteIdent == nil {
			ident, err := NewIdentity(key.Hashname).WithKeys(map[uint8][]byte{key.CSID: key.Key}, key.Parts)
			if err != nil {
				// drop; unable to create session
				return nil, false
			}

			x.remoteIdent = ident
		}

	}

	ident, err = NewIdentity(
		cipherset.Keys{handshake.CSID(): handshake.PublicKey()},
		handshake.Parts(),
		nil,
	)
	if err != nil {
		// drop; invalid identity
		return nil, false
	}

	if x.remoteIdent != nil && x.remoteIdent.Hashname() != ident.Hashname() {
		// drop; invalid hashname
		return nil, false
	}

	if !x.cipher.ApplyHandshake(handshake) {
		// drop; handshake was rejected by the cipherset
		return nil, false
	}

	if x.remoteIdent == nil {
		x.remoteIdent = ident
	}

	if x.isLocalSeq(at) {
		x.resetBreak()
		x.addressBook.ReceivedHandshake(pipe)

	} else {
		x.addressBook.AddPipe(pipe)

		response, err = x.generateHandshake(at)
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
		buf       [1500]byte
		csid      uint8
		err       error
	)

	if !msg.IsHandshake {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedHandshake(msg, nil, "invalid packet")
		return false
	}

	pkt, err = lob.Decode(msg.Data)
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, err)
		x.traceDroppedHandshake(msg, nil, err.Error())
		return false
	}

	hdr := pkt.Header()
	if !hdr.IsBinary() && len(hdr.Bytes) != 1 {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
		x.traceDroppedHandshake(msg, nil, "invalid header")
		return false
	}
	csid = uint8(hdr.Bytes[0])

	handshake, err = cipherset.DecryptHandshake(csid, x.localIdent.keys[csid], pkt.Body(buf[:0]))
	if err != nil {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, err)
		x.traceDroppedHandshake(msg, nil, err.Error())
		return false
	}

	resp, ok := x.applyHandshake(handshake, msg.Pipe)
	if !ok {
		x.exchangeHooks.DropPacket(msg.Data.Get(nil), msg.Pipe, nil)
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
