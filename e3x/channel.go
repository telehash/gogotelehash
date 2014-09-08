package e3x

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/util/events"
	"bitbucket.org/simonmenke/go-telehash/util/scheduler"
)

type UnreachableEndpointError hashname.H

func (err UnreachableEndpointError) Error() string {
	return "e3x: unreachable endpoint " + string(err)
}

var ErrTimeout = errors.New("e3x: deadline reached")

type BrokenChannelError struct {
	hn  hashname.H
	typ string
	id  uint32
}

func (err *BrokenChannelError) Error() string {
	return fmt.Sprintf("e3x: broken channel (type=%s id=%d hashname=%s)", err.typ, err.id, err.hn)
}

type ChannelState uint8

const (
	OpeningChannelState ChannelState = iota
	OpenChannelState
	EndedChannelState
	BrokenChannelState
)

const (
	c_READ_BUFFER_SIZE  = 100
	c_WRITE_BUFFER_SIZE = 100
)

type Channel struct {
	serverside bool
	id         uint32
	typ        string
	hashname   hashname.H
	reliable   bool
	broken     bool
	closing    bool

	oSeq         int // highest seq in write stream
	iBufferedSeq int // highest buffered seq in read stream
	iSeenSeq     int // highest seen seq in read stream
	iSeq         int // highest seq in read stream
	oAckedSeq    int // highest acked seq in write stream
	iAckedSeq    int // highest acked seq in read stream

	deliveredEnd bool
	receivedEnd  bool
	readEnd      bool

	writeDeadlineReached bool
	readDeadlineReached  bool

	qReceive           []*opReceivePacket
	qDeliver           []*opDeliverPacket
	qClose             []*opCloseChannel
	cReceivePacket     chan *opReceivePacket
	cDeliverPacket     chan *opDeliverPacket
	cCloseChannel      chan *opCloseChannel
	fDeliverPacket     func(*lob.Packet)
	fUnregisterChannel func(*Channel)
	subscribers        *events.Hub // belongs to endpoint

	readBuffer  map[uint32]*readBufferEntry
	writeBuffer map[uint32]*writeBufferEntry

	tReadDeadline  *scheduler.Event
	tOpenDeadline  *scheduler.Event
	tCloseDeadline *scheduler.Event
	lastSentAck    time.Time
}

type opRegisterChannel struct {
	ch   *Channel
	cErr chan error
}

type opDeliverPacket struct {
	ch    *Channel
	pkt   *lob.Packet
	queue bool
	cErr  chan error
}

type opReceivePacket struct {
	ch    *Channel
	pkt   *lob.Packet
	queue bool
	cErr  chan error
}

type opCloseChannel struct {
	ch      *Channel
	pkt     *lob.Packet
	deliver *opDeliverPacket
	receive *opReceivePacket
	cErr    chan error
}

type readBufferEntry struct {
	pkt *lob.Packet
	seq uint32
	end bool
}

type writeBufferEntry struct {
	pkt        *lob.Packet
	end        bool
	lastResend time.Time
}

func newChannel(hn hashname.H, typ string, reliable bool, serverside bool) *Channel {
	return &Channel{
		hashname:     hn,
		typ:          typ,
		reliable:     reliable,
		serverside:   serverside,
		readBuffer:   make(map[uint32]*readBufferEntry, c_READ_BUFFER_SIZE),
		writeBuffer:  make(map[uint32]*writeBufferEntry, c_WRITE_BUFFER_SIZE),
		oSeq:         -1,
		iBufferedSeq: -1,
		iSeenSeq:     -1,
		iSeq:         -1,
		oAckedSeq:    -1,
		iAckedSeq:    -1,
	}
}

func (c *Channel) RemoteHashname() hashname.H {
	return c.hashname
}

func (c *Channel) register_with_scheduler(s *scheduler.Scheduler) {
	c.tReadDeadline = s.NewEvent(c.on_read_deadline_reached)
	c.tOpenDeadline = s.NewEvent(c.on_open_deadline_reached)
	c.tCloseDeadline = s.NewEvent(c.on_close_deadline_reached)
	c.tOpenDeadline.ScheduleAfter(60 * time.Second)
}

func (c *Channel) register_with_endpoint(e *Endpoint) {
	c.cDeliverPacket = e.cDeliverPacket
	c.cReceivePacket = e.cReceivePacket
	c.cCloseChannel = e.cCloseChannel
	c.subscribers = &e.subscribers
}

func (c *Channel) register_with_exchange(x *exchange) {
	c.fDeliverPacket = x.deliver_packet
	c.fUnregisterChannel = x.unregister_channel
}

func (e *Endpoint) Dial(addr *Addr, typ string, reliable bool) (*Channel, error) {
	err := e.DialExchange(addr)
	if err != nil {
		return nil, err
	}

	ch := newChannel(addr.hashname, typ, reliable, false)

	{ // register channel
		op := opRegisterChannel{ch: ch, cErr: make(chan error)}
		e.cRegisterChannel <- &op
		err := <-op.cErr
		if err != nil {
			return nil, err
		}
	}

	return ch, nil
}

func (c *Channel) WritePacket(pkt *lob.Packet) error {
	if c == nil {
		return os.ErrInvalid
	}

	op := opDeliverPacket{c, pkt, true, make(chan error)}
	c.cDeliverPacket <- &op
	return waitForError(op.cErr)
}

func (c *Channel) ReadPacket() (*lob.Packet, error) {
	if c == nil {
		return nil, os.ErrInvalid
	}

	op := opReceivePacket{c, nil, true, make(chan error)}
	c.cReceivePacket <- &op
	err := waitForError(op.cErr)
	return op.pkt, err
}

func (c *Channel) Close() error {
	if c == nil {
		return os.ErrInvalid
	}

	op := opCloseChannel{c, nil, nil, nil, make(chan error)}
	c.cCloseChannel <- &op
	return waitForError(op.cErr)
}

func (c *Channel) deliver_packet(op *opDeliverPacket) {
	var pkt = op.pkt

	if c.broken {
		// tracef("WritePacket() => broken")
		// When a channel is marked as broken the all writes
		// must return a BrokenChannelError.
		op.cErr <- &BrokenChannelError{c.hashname, c.typ, c.id}
		return
	}

	if c.writeDeadlineReached {
		// tracef("WritePacket() => timeout")
		// When a channel reached a write deadline then all writes
		// must return a ErrTimeout.
		op.cErr <- ErrTimeout
		return
	}

	if c.deliveredEnd {
		// tracef("WritePacket() => ended")
		// When a channel sent a packet with the "end" header set
		// then all subsequent writes must return io.EOF
		op.cErr <- io.EOF
		return
	}

	if c.serverside && c.iSeq == -1 {
		// tracef("WritePacket() => opening")
		// When a server channel did not (yet) read an initial packet
		// then all writes must be deferred.
		if op.queue {
			c.qDeliver = append(c.qDeliver, op)
		}
		op.cErr <- errDeferred
		return
	}

	if !c.serverside && c.iSeq == -1 && c.oSeq >= 0 {
		// tracef("WritePacket() => opening")
		// When a client channel sent a packet but did not yet read a response
		// to the initial packet then subsequent writes must be deferred.
		if op.queue {
			c.qDeliver = append(c.qDeliver, op)
		}
		op.cErr <- errDeferred
		return
	}

	if len(c.writeBuffer) >= c_WRITE_BUFFER_SIZE {
		// tracef("WritePacket() => blocking")
		// When a channel filled its write buffer then
		// all writes must be deferred.
		if op.queue {
			c.qDeliver = append(c.qDeliver, op)
		}
		op.cErr <- errDeferred
		return
	}

	c.oSeq++
	pkt.Header().SetUint32("c", c.id)
	if c.reliable {
		pkt.Header().SetUint32("seq", uint32(c.oSeq))
	}
	if !c.serverside && c.oSeq == 0 {
		pkt.Header().SetString("type", c.typ)
	}

	end, _ := pkt.Header().GetBool("end")
	if end {
		c.deliveredEnd = true
	}

	if c.reliable {
		c.apply_ack_headers(pkt)
		c.writeBuffer[uint32(c.oSeq)] = &writeBufferEntry{pkt, end, time.Time{}}
	}

	c.fDeliverPacket(pkt)
	op.cErr <- nil
	// tracef("WritePacket() => sent")

	if c.oSeq == 0 && c.serverside {
		c.tOpenDeadline.Cancel()
	}

	if c.oSeq == 0 || end {
		// first packet is sent
		c.process_receive_queue()
	}

	return
}

func (c *Channel) receive_packet(op *opReceivePacket) {
	if c.broken {
		// tracef("ReadPacket() => broken")
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		op.cErr <- &BrokenChannelError{c.hashname, c.typ, c.id}
		return
	}

	if c.readDeadlineReached {
		// tracef("ReadPacket() => timeout")
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		op.cErr <- ErrTimeout
		return
	}

	if c.readEnd {
		// tracef("ReadPacket() => ended")
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		op.cErr <- io.EOF
		return
	}

	if c.serverside && c.oSeq == -1 && c.iSeq >= 0 {
		// tracef("server.ReadPacket() => opening")
		// When a server channel read a packet but did not yet respond
		// to the initial packet then subsequent reads must be deferred.
		if op.queue {
			c.qReceive = append(c.qReceive, op)
		}
		op.cErr <- errDeferred
		return
	}

	if !c.serverside && c.oSeq == -1 {
		// tracef("client.ReadPacket() => opening")
		// When a client channel did not (yet) send an initial packet
		// then all reads must be deferred.
		if op.queue {
			c.qReceive = append(c.qReceive, op)
		}
		op.cErr <- errDeferred
		return
	}

	rSeq := uint32(c.iSeq + 1)
	e := c.readBuffer[rSeq]
	if e == nil {
		// tracef("ReadPacket() => blocking")
		// Packet has not yet been received
		// defer the read
		if op.queue {
			c.qReceive = append(c.qReceive, op)
		}
		op.cErr <- errDeferred
		return
	}

	c.iSeq = int(rSeq)
	delete(c.readBuffer, rSeq)

	if e.end {
		c.deliver_ack()
		c.readEnd = e.end
	}

	// tracef("ReadPacket() => returned packet")
	{ // clean headers
		h := e.pkt.Header()
		delete(h, "c")
		delete(h, "type")
		delete(h, "seq")
		delete(h, "ack")
		delete(h, "miss")
		delete(h, "end")
	}

	if len(e.pkt.Body) == 0 && len(e.pkt.Header()) == 0 && e.end {
		// read empty `end` packet
		op.pkt = nil
		op.cErr <- io.EOF
	} else {
		// nor mal packet
		op.pkt = e.pkt
		op.cErr <- nil
	}

	if c.iSeq == 0 && !c.serverside {
		c.tOpenDeadline.Cancel()
	}

	if c.iSeq == 0 {
		// first packet is read
		c.process_deliver_queue()
	}

	c.maybe_deliver_ack()
	return
}

func (c *Channel) received_packet(pkt *lob.Packet) {
	var (
		seq, hasSeq   = pkt.Header().GetUint32("seq")
		ack, hasAck   = pkt.Header().GetUint32("ack")
		miss, hasMiss = pkt.Header().GetUint32Slice("miss")
		end, hasEnd   = pkt.Header().GetBool("end")
	)

	if !c.reliable {
		// unreliable channels (internaly) emulate reliable channels.
		seq = uint32(c.iBufferedSeq + 1)
		hasSeq = true

	} else {
		// determine what to drop from the write buffer
		if hasAck {
			var (
				oldAck = c.oAckedSeq
			)

			if c.oAckedSeq < int(ack) {
				c.oAckedSeq = int(ack)
			}

			for i := oldAck + 1; i <= int(ack); i++ {
				// tracef("W-BUF->DEL(%d)", i)
				delete(c.writeBuffer, uint32(i))
			}
		}

		if hasMiss {
			c.process_missing_packets(miss)
		}
	}

	if !hasSeq {
		// tracef("ReceivePacket() => drop // no seq")
		// drop: is not a valid packet
		if hasAck {
			c.process_deliver_queue()
			c.process_receive_queue()
			c.process_close_queue()
		}
		return
	}

	if c.reliable && c.iSeenSeq < int(seq) {
		// record highest seen seq
		c.iSeenSeq = int(seq)
	}

	if int(seq) <= c.iSeq {
		// tracef("ReceivePacket() => drop // seq is already read")
		// drop: the reader already read a packet with this seq
		return
	}

	if _, found := c.readBuffer[seq]; found {
		// tracef("ReceivePacket() => drop // seq is already buffered")
		// drop: a packet with this seq is already buffered
		return
	}

	if len(c.readBuffer) >= c_READ_BUFFER_SIZE {
		// tracef("ReceivePacket() => drop // buffer is full")
		// drop: the read buffer is full
		return
	}

	if c.iBufferedSeq < int(seq) {
		c.iBufferedSeq = int(seq)
	}
	if end && hasEnd {
		c.receivedEnd = end
		c.deliver_ack()
	}

	// tracef("ReceivePacket() => buffered")
	c.readBuffer[seq] = &readBufferEntry{pkt, seq, end}

	c.process_receive_queue()
	c.process_close_queue()
}

func (c *Channel) close(op *opCloseChannel) {
	if c.broken {
		// tracef("Close() => broken")
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		op.cErr <- &BrokenChannelError{c.hashname, c.typ, c.id}
		return
	}

	if !c.closing {
		c.tCloseDeadline.ScheduleAfter(1 * time.Minute)
		c.closing = true
	}

	if !c.deliveredEnd {
		if op.pkt == nil {
			op.pkt = &lob.Packet{}
			op.pkt.Header().SetBool("end", true)
		}

		if op.deliver == nil {
			op.deliver = &opDeliverPacket{c, op.pkt, false, make(chan error, 1)}
		}

		c.deliver_packet(op.deliver)

		err := <-op.deliver.cErr
		if err == errDeferred {
			// tracef("Close() => deliver `end` deferred")
			c.qClose = append(c.qClose, op)
			op.cErr <- errDeferred
			return
		}
		if err != nil {
			// tracef("Close() => deliver `end` err: %s", err)
			op.cErr <- err
			return
		}
	}

	// flush all bending reads
	if op.receive == nil {
		op.receive = &opReceivePacket{c, nil, false, make(chan error, 1)}
	}
	for {
		c.receive_packet(op.receive)

		err := <-op.receive.cErr
		if err == errDeferred {
			// tracef("Close() => receive `end` deferred")
			c.qClose = append(c.qClose, op)
			op.cErr <- errDeferred
			return
		}
		if err == io.EOF {
			// tracef("Close() => received `end`")
			break
		}
		if err != nil {
			// tracef("Close() => receive `end` err: %s", err)
			op.cErr <- err
			return
		}
	}

	if c.reliable && len(c.writeBuffer) > 0 {
		// tracef("Close() // write buffer not empty")
		c.qClose = append(c.qClose, op)
		op.cErr <- errDeferred
		return
	}

	// tracef("Close() // closed")

	c.unregister()

	c.process_receive_queue()
	c.process_deliver_queue()
	op.cErr <- nil
}

func (c *Channel) buildMissList() []uint32 {
	var miss = make([]uint32, 0, 50)
	for i := c.iSeq + 1; i <= c.iSeenSeq; i++ {
		if _, p := c.readBuffer[uint32(i)]; !p {
			miss = append(miss, uint32(i))
		}
	}
	if len(miss) > 100 {
		miss = miss[:100]
	}
	return miss
}

func (c *Channel) process_missing_packets(miss []uint32) {
	var (
		omiss       = c.buildMissList()
		now         = time.Now()
		one_sec_ago = now.Add(-1 * time.Second)
	)

	// tracef("MISS: %v", miss)
	for _, seq := range miss {
		e, f := c.writeBuffer[seq]
		if !f || e == nil {
			continue
		}

		if e.lastResend.After(one_sec_ago) {
			continue
		}

		// tracef("MISS->SND(%d)", seq)
		e.pkt.Header().SetUint32("ack", uint32(c.iSeq))
		e.pkt.Header().SetUint32Slice("miss", omiss)
		e.lastResend = now

		c.fDeliverPacket(e.pkt)
	}
}

func (c *Channel) maybe_deliver_ack() {
	var (
		shouldAck bool
	)

	if !c.reliable {
		return
	}

	if c.iSeq < 0 {
		return // nothin to ack
	}

	if c.iSeq-c.iAckedSeq > 30 {
		shouldAck = true
	}

	if time.Since(c.lastSentAck) > 10*time.Second {
		shouldAck = true
	}

	if shouldAck {
		c.deliver_ack()
	}
}

func (c *Channel) deliver_ack() {
	if !c.reliable {
		return
	}

	pkt := &lob.Packet{}
	pkt.Header().SetUint32("c", c.id)
	c.apply_ack_headers(pkt)
	c.fDeliverPacket(pkt)
}

func (c *Channel) apply_ack_headers(pkt *lob.Packet) {
	if !c.reliable {
		return
	}

	if c.iSeq == -1 {
		// nothin to ack
		return
	}

	pkt.Header().SetUint32("ack", uint32(c.iSeq))
	pkt.Header().SetUint32Slice("miss", c.buildMissList())

	c.iAckedSeq = c.iSeq
	c.lastSentAck = time.Now()

	// tracef("ACK(%d)", c.iSeq)
}

func (c *Channel) on_read_deadline_reached() {
	c.readDeadlineReached = true
	c.process_receive_queue()
	c.process_close_queue()
}

func (c *Channel) on_open_deadline_reached() {
	c.broken = true
	c.process_receive_queue()
	c.process_deliver_queue()
	c.process_close_queue()
	c.unregister()
}

func (c *Channel) on_close_deadline_reached() {
	c.broken = true
	c.process_receive_queue()
	c.process_deliver_queue()
	c.process_close_queue()
	c.unregister()
}

func (c *Channel) process_deliver_queue() {
	var (
		q = c.qDeliver
	)
	c.qDeliver = nil

	for _, op := range q {
		c.deliver_packet(op)
	}
}

func (c *Channel) process_receive_queue() {
	var (
		q = c.qReceive
	)
	c.qReceive = nil

	for _, op := range q {
		c.receive_packet(op)
	}
}

func (c *Channel) process_close_queue() {
	var (
		q = c.qClose
	)
	c.qClose = nil

	for _, op := range q {
		c.close(op)
	}
}

func (c *Channel) unregister() {
	c.tOpenDeadline.Cancel()
	c.tReadDeadline.Cancel()
	c.fUnregisterChannel(c)
	c.subscribers.Emit(&ChannelClosedEvent{c})
}

func (e *Endpoint) register_channel(op *opRegisterChannel) error {
	x := e.hashnames[op.ch.hashname]
	if x == nil || x.state != openedExchangeState {
		return UnreachableEndpointError(op.ch.hashname)
	}

	return x.register_channel(op.ch)
}

func (x *exchange) register_channel(ch *Channel) error {
	var wasIdle = len(x.channels) == 0

	if ch.id == 0 {
		ch.id = x.nextChannelId()
	}
	x.channels[ch.id] = ch

	if wasIdle {
		x.tExpire.Cancel()
	}

	ch.register_with_exchange(x)
	ch.register_with_endpoint(x.endpoint)
	ch.register_with_scheduler(x.endpoint.scheduler)

	x.endpoint.subscribers.Emit(&ChannelOpenedEvent{ch})

	return nil
}

func (x *exchange) unregister_channel(ch *Channel) {
	delete(x.channels, ch.id)

	if len(x.channels) == 0 {
		x.tExpire.ScheduleAfter(2 * time.Minute)
	}
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
