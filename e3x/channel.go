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

	readBuffer  map[uint32]*readBufferEntry
	writeBuffer map[uint32]*writeBufferEntry

	cChannelWrite  chan opChannelWrite
	cChannelRead   chan opChannelRead
	cExchangeWrite chan opExchangeWrite
	cExchangeRead  chan opExchangeRead
	cChannelClose  chan opChannelClose

	tOpenDeadline  *time.Timer
	tCloseDeadline *time.Timer

	// should be removed:
	x                  *exchange
	qClose             []*opChannelClose
	fUnregisterChannel func(*Channel)
	subscribers        *events.Hub // belongs to endpoint

	tReadDeadline *scheduler.Event
	lastSentAck   time.Time
}

type opRegisterChannel struct {
	ch   *Channel
	cErr chan error
}

type opChannelWrite struct {
	pkt  *lob.Packet
	cErr chan error
}

type opChannelRead struct {
	pkt *lob.Packet
	err error
}

type opChannelClose struct {
	cErr chan error
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
		hashname:      hn,
		typ:           typ,
		reliable:      reliable,
		serverside:    serverside,
		readBuffer:    make(map[uint32]*readBufferEntry, c_READ_BUFFER_SIZE),
		writeBuffer:   make(map[uint32]*writeBufferEntry, c_WRITE_BUFFER_SIZE),
		cChannelWrite: make(chan opChannelWrite),
		cChannelRead:  make(chan opChannelRead),
		cChannelClose: make(chan opChannelClose),
		oSeq:          -1,
		iBufferedSeq:  -1,
		iSeenSeq:      -1,
		iSeq:          -1,
		oAckedSeq:     -1,
		iAckedSeq:     -1,
	}
}

func (c *Channel) run() {
	defer func() {
		close(c.cChannelRead)
		close(c.cChannelWrite)
	}()

	c.tOpenDeadline = time.NewTimer(60 * time.Second)

	for {
		var (
			cChannelWrite = c.cChannelWrite
			cChannelRead  = c.cChannelRead
			cChannelClose = c.cChannelClose
		)

		if c.block_write() {
			cChannelWrite = nil
		}

		if c.block_read() {
			cChannelRead = nil
		}

		if c.block_close() {
			cChannelClose = nil
		}

		select {

		case op := <-cChannelWrite:
			c.deliver_packet(op)

		case op, closed := <-c.cExchangeRead:
			if closed {
				c.broken = true
				return
			}
			c.received_packet(op.pkt)

		case cChannelRead <- c.peek_packet():
			c.read_packet()

		case op := <-cChannelClose:
			c.close(op)

		case <-c.tOpenDeadline.C:
			c.broken = true
			return

		}
	}
}

func (c *Channel) RemoteHashname() hashname.H {
	return c.hashname
}

func (c *Channel) register_with_scheduler(s *scheduler.Scheduler) {
	c.tReadDeadline = s.NewEvent(c.on_read_deadline_reached)
}

func (c *Channel) register_with_endpoint(e *Endpoint) {
	c.subscribers = &e.subscribers
}

func (c *Channel) register_with_exchange(x *exchange) {
	c.cExchangeWrite = x.cExchangeWrite
	c.cExchangeRead = x.cExchangeRead
	c.fUnregisterChannel = x.unregister_channel
	c.x = x
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

	op := opChannelWrite{pkt, make(chan error)}
	c.cChannelWrite <- op
	return waitForError(op.cErr)
}

func (c *Channel) ReadPacket() (*lob.Packet, error) {
	if c == nil {
		return nil, os.ErrInvalid
	}

	op, closed := <-c.cChannelRead
	if closed {
		return nil, io.EOF
	}
	if op.err != nil {
		return nil, op.err
	}
	return op.pkt, nil
}

func (c *Channel) Close() error {
	if c == nil {
		return os.ErrInvalid
	}

	op := opChannelClose{make(chan error)}
	c.cChannelClose <- op
	return <-op.cErr
}

func (c *Channel) block_write() bool {
	if c.serverside && c.iSeq == -1 {
		// tracef("WritePacket() => opening")
		// When a server channel did not (yet) read an initial packet
		// then all writes must be deferred.
		return true
	}

	if !c.serverside && c.iSeq == -1 && c.oSeq >= 0 {
		// tracef("WritePacket() => opening")
		// When a client channel sent a packet but did not yet read a response
		// to the initial packet then subsequent writes must be deferred.
		return true
	}

	if len(c.writeBuffer) >= c_WRITE_BUFFER_SIZE {
		// tracef("WritePacket() => blocking")
		// When a channel filled its write buffer then
		// all writes must be deferred.
		return true
	}

	return false
}

func (c *Channel) deliver_packet(op opChannelWrite) {
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

	c.cExchangeWrite <- opExchangeWrite{c.x, pkt, op.cErr}
	// tracef("WritePacket() => sent")

	if c.oSeq == 0 && c.serverside {
		c.tOpenDeadline.Stop()
	}

	return
}

func (c *Channel) block_read() bool {
	if c.broken {
		// tracef("ReadPacket() => broken")
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		return false
	}

	if c.readDeadlineReached {
		// tracef("ReadPacket() => timeout")
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		return false
	}

	if c.readEnd {
		// tracef("ReadPacket() => ended")
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		return false
	}

	if c.serverside && c.oSeq == -1 && c.iSeq >= 0 {
		// tracef("server.ReadPacket() => opening")
		// When a server channel read a packet but did not yet respond
		// to the initial packet then subsequent reads must be deferred.
		return true
	}

	if !c.serverside && c.oSeq == -1 {
		// tracef("client.ReadPacket() => opening")
		// When a client channel did not (yet) send an initial packet
		// then all reads must be deferred.
		return true
	}

	rSeq := uint32(c.iSeq + 1)
	e := c.readBuffer[rSeq]
	if e == nil {
		// tracef("ReadPacket() => blocking")
		// Packet has not yet been received
		// defer the read
		return true
	}

	return false
}

func (c *Channel) peek_packet() opChannelRead {
	if c.broken {
		// tracef("ReadPacket() => broken")
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		return opChannelRead{err: &BrokenChannelError{c.hashname, c.typ, c.id}}
	}

	if c.readDeadlineReached {
		// tracef("ReadPacket() => timeout")
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		return opChannelRead{err: ErrTimeout}
	}

	if c.readEnd {
		// tracef("ReadPacket() => ended")
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		return opChannelRead{err: io.EOF}
	}

	rSeq := uint32(c.iSeq + 1)
	e := c.readBuffer[rSeq]

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
		return opChannelRead{err: io.EOF}
	}

	return opChannelRead{pkt: e.pkt}
}

func (c *Channel) read_packet() {
	rSeq := uint32(c.iSeq + 1)
	e := c.readBuffer[rSeq]

	c.iSeq = int(rSeq)
	delete(c.readBuffer, rSeq)

	if e.end {
		c.deliver_ack()
		c.readEnd = e.end
	}

	if c.iSeq == 0 && !c.serverside {
		c.tOpenDeadline.Stop()
	}

	c.maybe_deliver_ack()
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

			if hasMiss {
				c.process_missing_packets(ack, miss)
			}
		}
	}

	if !hasSeq {
		// tracef("ReceivePacket() => drop // no seq")
		// drop: is not a valid packet
		if hasAck {
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

	c.process_close_queue()
}

func (c *Channel) block_close() bool {
	if c.broken {
		return false
	}

	if c.closing {
		return true
	}

	if c.block_write() {
		return true
	}

	return false
}

func (c *Channel) close(op opChannelClose) {
	if c.broken {
		// tracef("Close() => broken")
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		op.cErr <- &BrokenChannelError{c.hashname, c.typ, c.id}
		return
	}

	if !c.closing {
		c.tCloseDeadline = time.NewTimer(60 * time.Second)
		c.closing = true
	}

	if !c.deliveredEnd {
		pkt := &lob.Packet{}
		pkt.Header().SetBool("end", true)
		opDeliver := opChannelWrite{pkt, make(chan error, 1)}

		c.deliver_packet(opDeliver)

		err := <-opDeliver.cErr
		if err != nil {
			// tracef("Close() => deliver `end` err: %s", err)
			c.broken = true
			op.cErr <- err
			return
		}
	}

	// flush all pending reads
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
	op.cErr <- nil
}

func (c *Channel) buildMissList() []uint32 {
	var (
		miss = make([]uint32, 0, 50)
		last = c.iSeq
	)
	for i := c.iSeq + 1; i <= c.iSeenSeq; i++ {
		if _, p := c.readBuffer[uint32(i)]; !p {
			miss = append(miss, uint32(i-last))
			last = i
		}
	}
	if len(miss) > 100 {
		miss = miss[:100]
	}
	return miss
}

func (c *Channel) process_missing_packets(ack uint32, miss []uint32) {
	var (
		omiss       = c.buildMissList()
		now         = time.Now()
		one_sec_ago = now.Add(-1 * time.Second)
		last        = ack
	)

	// tracef("MISS: %v", miss)
	for _, delta := range miss {
		seq := last + delta
		last = seq

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

		c.cExchangeWrite <- opExchangeWrite{c.x, e.pkt, nil}
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
	c.cExchangeWrite <- opExchangeWrite{c.x, pkt, nil}
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
	c.process_close_queue()
}

func (c *Channel) on_close_deadline_reached() {
	c.broken = true
	c.process_close_queue()
	c.unregister()
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
