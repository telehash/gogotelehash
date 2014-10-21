package e3x

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
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

const (
	c_READ_BUFFER_SIZE  = 100
	c_WRITE_BUFFER_SIZE = 100
)

type Channel struct {
	mtx      sync.Mutex
	cndRead  *sync.Cond
	cndWrite *sync.Cond
	cndClose *sync.Cond

	x          exchangeI
	serverside bool
	id         uint32
	typ        string
	hashname   hashname.H
	reliable   bool
	broken     bool

	oSeq         int // highest seq in write stream
	iBufferedSeq int // highest buffered seq in read stream
	iSeenSeq     int // highest seen seq in read stream
	iSeq         int // highest seq in read stream
	oAckedSeq    int // highest acked seq in write stream
	iAckedSeq    int // highest acked seq in read stream

	deliveredEnd bool
	receivedEnd  bool
	readEnd      bool

	openDeadlineReached  bool
	writeDeadlineReached bool
	readDeadlineReached  bool
	closeDeadlineReached bool

	readBuffer  map[uint32]*readBufferEntry
	writeBuffer map[uint32]*writeBufferEntry

	tOpenDeadline  *time.Timer
	tCloseDeadline *time.Timer
	tReadDeadline  *time.Timer
	lastSentAck    time.Time
}

type exchangeI interface {
	deliver_packet(pkt *lob.Packet) error
	unregister_channel(channelId uint32)
	RemoteAddr() *Addr
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

func newChannel(
	hn hashname.H, typ string,
	reliable bool, serverside bool,
	x exchangeI,
) *Channel {
	c := &Channel{
		x:            x,
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

	c.cndRead = sync.NewCond(&c.mtx)
	c.cndWrite = sync.NewCond(&c.mtx)
	c.cndClose = sync.NewCond(&c.mtx)

	c.set_open_deadline()

	return c
}

func (c *Channel) RemoteHashname() hashname.H {
	// hashname is constant

	return c.hashname
}

func (c *Channel) RemoteAddr() *Addr {
	return c.x.RemoteAddr()
}

func (e *Endpoint) Open(addr *Addr, typ string, reliable bool) (*Channel, error) {
	x, err := e.Dial(addr)
	if err != nil {
		return nil, err
	}

	return x.Open(typ, reliable)
}

func (c *Channel) WritePacket(pkt *lob.Packet) error {
	if c == nil {
		return os.ErrInvalid
	}

	c.mtx.Lock()
	for c.block_write() {
		c.cndWrite.Wait()
	}

	err := c.write(pkt)

	if !c.block_write() {
		c.cndWrite.Signal()
	}

	c.mtx.Unlock()
	return err
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

func (c *Channel) write(pkt *lob.Packet) error {
	if c.broken {
		// tracef("WritePacket() => broken")
		// When a channel is marked as broken the all writes
		// must return a BrokenChannelError.
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	if c.writeDeadlineReached {
		// tracef("WritePacket() => timeout")
		// When a channel reached a write deadline then all writes
		// must return a ErrTimeout.
		return ErrTimeout
	}

	if c.deliveredEnd {
		// tracef("WritePacket() => ended")
		// When a channel sent a packet with the "end" header set
		// then all subsequent writes must return io.EOF
		return io.EOF
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
		c.set_close_deadline()
	}

	if c.reliable {
		c.apply_ack_headers(pkt)
		c.writeBuffer[uint32(c.oSeq)] = &writeBufferEntry{pkt, end, time.Time{}}
	}

	err := c.x.deliver_packet(pkt)
	if err != nil {
		return err
	}

	if c.oSeq == 0 && c.serverside {
		c.unset_open_deadline()
	}

	return nil
}

func (c *Channel) ReadPacket() (*lob.Packet, error) {
	if c == nil {
		return nil, os.ErrInvalid
	}

	c.mtx.Lock()
	for c.block_read() {
		c.cndRead.Wait()
	}

	pkt, err := c.peek_packet()
	if pkt != nil {
		c.read_packet()
	}

	c.mtx.Unlock()
	return pkt, err
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
	if c.readBuffer[rSeq] == nil {
		// tracef("ReadPacket() => blocking")
		// Packet has not yet been received
		// defer the read
		return true
	}

	return false
}

func (c *Channel) peek_packet() (*lob.Packet, error) {
	if c.broken {
		// tracef("ReadPacket() => broken")
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		return nil, &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	if c.readDeadlineReached {
		// tracef("ReadPacket() => timeout")
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		return nil, ErrTimeout
	}

	if c.readEnd {
		// tracef("ReadPacket() => ended")
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		return nil, io.EOF
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
		c.read_packet()
		return nil, io.EOF
	}

	return e.pkt, nil
}

func (c *Channel) read_packet() {
	rSeq := uint32(c.iSeq + 1)
	e := c.readBuffer[rSeq]

	c.iSeq = int(rSeq)
	delete(c.readBuffer, rSeq)

	if e.end {
		c.deliver_ack()
		c.readEnd = true
	}

	if c.iSeq == 0 && !c.serverside {
		c.unset_open_deadline()
	}

	c.maybe_deliver_ack()

	if c.deliveredEnd && !c.block_close() {
		c.cndClose.Signal()
	}
	if !c.block_read() {
		c.cndRead.Signal()
	}
	if !c.block_write() {
		c.cndWrite.Signal()
	}
}

func (c *Channel) received_packet(pkt *lob.Packet) {
	c.mtx.Lock()

	if c.broken {
		c.mtx.Unlock()
		return
	}

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
				oldAck  = c.oAckedSeq
				changed bool
			)

			if c.oAckedSeq < int(ack) {
				c.oAckedSeq = int(ack)
				changed = true
			}

			for i := oldAck + 1; i <= int(ack); i++ {
				// tracef("W-BUF->DEL(%d)", i)
				delete(c.writeBuffer, uint32(i))
				changed = true
			}

			if changed {
				c.cndWrite.Signal()
				if c.deliveredEnd {
					c.cndClose.Signal()
				}
			}

			if hasMiss {
				c.process_missing_packets(ack, miss)
			}
		}
	}

	if !hasSeq {
		// tracef("ReceivePacket() => drop // no seq")
		// drop: is not a valid packet
		c.mtx.Unlock()
		return
	}

	if c.reliable && c.iSeenSeq < int(seq) {
		// record highest seen seq
		c.iSeenSeq = int(seq)
	}

	if int(seq) <= c.iSeq {
		// tracef("ReceivePacket() => drop // seq is already read")
		// drop: the reader already read a packet with this seq
		c.mtx.Unlock()
		return
	}

	if _, found := c.readBuffer[seq]; found {
		// tracef("ReceivePacket() => drop // seq is already buffered")
		// drop: a packet with this seq is already buffered
		c.mtx.Unlock()
		return
	}

	if len(c.readBuffer) >= c_READ_BUFFER_SIZE {
		// tracef("ReceivePacket() => drop // buffer is full")
		// drop: the read buffer is full
		c.mtx.Unlock()
		return
	}

	if c.iBufferedSeq < int(seq) {
		c.iBufferedSeq = int(seq)
	}
	if end && hasEnd {
		c.receivedEnd = true
		c.deliver_ack()
	}

	// tracef("ReceivePacket() => buffered")
	c.readBuffer[seq] = &readBufferEntry{pkt, seq, end}

	c.cndRead.Signal()
	c.mtx.Unlock()
}

func (c *Channel) Errorf(format string, args ...interface{}) error {
	return c.Error(fmt.Errorf(format, args...))
}

func (c *Channel) Error(err error) error {
	if c == nil {
		return os.ErrInvalid
	}

	c.mtx.Lock()

	if c.broken {
		// tracef("Close() => broken")
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		c.mtx.Unlock()
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	for c.block_write() {
		c.cndWrite.Wait()
	}

	if c.deliveredEnd {
		c.mtx.Unlock()
		return nil
	}

	pkt := &lob.Packet{}
	pkt.Header().SetString("err", err.Error())
	if err := c.write(pkt); err != nil {
		c.mtx.Unlock()
		return err
	}

	c.broken = true
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregister_channel(c.id)
	c.mtx.Unlock()
	return nil
}

func (c *Channel) Close() error {
	if c == nil {
		return os.ErrInvalid
	}

	c.mtx.Lock()

	if c.broken {
		// tracef("Close() => broken")
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		c.mtx.Unlock()
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	c.set_close_deadline()

	if !c.deliveredEnd {
		for c.block_write() {
			c.cndWrite.Wait()
		}

		if !c.deliveredEnd {
			pkt := &lob.Packet{}
			pkt.Header().SetBool("end", true)
			if err := c.write(pkt); err != nil {
				c.mtx.Unlock()
				return err
			}
		}
	}

	for {
		for c.block_read() {
			c.cndRead.Wait()
		}
		pkt, err := c.peek_packet()
		if pkt != nil {
			c.read_packet()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	for c.block_close() {
		c.cndClose.Wait()
	}

	if c.broken {
		// tracef("Close() => broken")
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		c.mtx.Unlock()
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	c.unset_open_deadline()
	c.unset_close_deadline()

	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregister_channel(c.id)
	c.mtx.Unlock()
	return nil
}

func (c *Channel) block_close() bool {
	if c.broken {
		return false
	}

	if !c.readEnd {
		return true
	}

	if c.reliable && len(c.writeBuffer) > 0 {
		return true
	}

	return false
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

		c.x.deliver_packet(e.pkt)
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
		return // nothing to ack
	}

	if c.iSeq-c.iAckedSeq >= 30 {
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
	c.x.deliver_packet(pkt)
	tracef("ACK serverside=%v hdr=%v", c.serverside, pkt.Header())
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
	if l := c.buildMissList(); len(l) > 0 {
		pkt.Header().SetUint32Slice("miss", c.buildMissList())
	}

	c.iAckedSeq = c.iSeq
	c.lastSentAck = time.Now()

	// tracef("ACK(%d)", c.iSeq)
}

func (c *Channel) set_close_deadline() {
	if c.tCloseDeadline == nil {
		if c.closeDeadlineReached {
			return
		}

		c.tCloseDeadline = time.AfterFunc(
			60*time.Second,
			c.on_close_deadline_reached,
		)
	}
}

func (c *Channel) unset_close_deadline() {
	if c.tCloseDeadline != nil {
		c.tCloseDeadline.Stop()
		c.tCloseDeadline = nil
	}
}

func (c *Channel) on_close_deadline_reached() {
	c.mtx.Lock()
	c.broken = true
	c.closeDeadlineReached = true
	c.unset_open_deadline()
	c.unset_close_deadline()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregister_channel(c.id)
	c.mtx.Unlock()
}

func (c *Channel) set_open_deadline() {
	if c.tOpenDeadline == nil {
		if c.openDeadlineReached {
			return
		}

		c.tOpenDeadline = time.AfterFunc(
			60*time.Second,
			c.on_open_deadline_reached,
		)
	}
}

func (c *Channel) unset_open_deadline() {
	if c.tOpenDeadline != nil {
		c.tOpenDeadline.Stop()
		c.tOpenDeadline = nil
	}
}

func (c *Channel) on_open_deadline_reached() {
	c.mtx.Lock()
	c.broken = true
	c.openDeadlineReached = true
	c.unset_open_deadline()
	c.unset_close_deadline()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregister_channel(c.id)
	c.mtx.Unlock()
}

func (c *Channel) forget() {
	c.mtx.Lock()
	c.broken = true
	c.openDeadlineReached = false
	c.unset_open_deadline()
	c.unset_close_deadline()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregister_channel(c.id)
	c.mtx.Unlock()
}
