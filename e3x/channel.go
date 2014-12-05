package e3x

import (
	"errors"
	"fmt"
	"github.com/telehash/gogotelehash/transports"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/util/bufpool"
)

var (
	_ net.Conn = (*Channel)(nil)
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
	cReadBufferSize  = 100
	cWriteBufferSize = 100
	earlyAdHocAck    = 50
	cBlankSeq        = uint32(0)
	cInitialSeq      = uint32(1)
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

	oSeq         uint32 // highest seq in write stream
	iBufferedSeq uint32 // highest buffered seq in read stream
	iSeenSeq     uint32 // highest seen seq in read stream
	iSeq         uint32 // highest seq in read stream
	oAckedSeq    uint32 // highest acked seq in write stream
	iAckedSeq    uint32 // highest acked seq in read stream

	deliveredEnd bool
	receivedEnd  bool
	readEnd      bool
	needsResend  bool

	openDeadlineReached  bool
	writeDeadlineReached bool
	readDeadlineReached  bool
	closeDeadlineReached bool

	readBuffer  readBufferSlice
	writeBuffer map[uint32]*writeBufferEntry

	tOpenDeadline  *time.Timer
	tCloseDeadline *time.Timer
	tReadDeadline  *time.Timer
	tWriteDeadline *time.Timer
	tResend        *time.Timer
	tAcker         *time.Timer
}

type exchangeI interface {
	deliverPacket(pkt *lob.Packet, dst transports.Addr) error
	unregisterChannel(channelID uint32)
	RemoteIdentity() *Identity
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
	dst        transports.Addr
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
		readBuffer:   make([]*readBufferEntry, 0, cReadBufferSize),
		writeBuffer:  make(map[uint32]*writeBufferEntry, cWriteBufferSize),
		oSeq:         cBlankSeq,
		iBufferedSeq: cBlankSeq,
		iSeenSeq:     cBlankSeq,
		iSeq:         cBlankSeq,
		oAckedSeq:    cBlankSeq,
		iAckedSeq:    cBlankSeq,
	}

	c.cndRead = sync.NewCond(&c.mtx)
	c.cndWrite = sync.NewCond(&c.mtx)
	c.cndClose = sync.NewCond(&c.mtx)

	c.setOpenDeadline()

	c.tReadDeadline = time.AfterFunc(10*time.Second, c.onReadDeadlineReached)
	c.tWriteDeadline = time.AfterFunc(10*time.Second, c.onWriteDeadlineReached)
	c.tReadDeadline.Stop()
	c.tWriteDeadline.Stop()

	if reliable {
		c.tResend = time.AfterFunc(1*time.Second, c.resendLastPacket)
		c.tAcker = time.AfterFunc(10*time.Second, c.autoDeliverAck)
	}

	return c
}

func (c *Channel) RemoteHashname() hashname.H {
	// hashname is constant

	return c.hashname
}

func (c *Channel) RemoteIdentity() *Identity {
	return c.x.RemoteIdentity()
}

func (c *Channel) Exchange() *Exchange {
	if x, ok := c.x.(*Exchange); ok && x != nil {
		return x
	}
	return nil
}

func (e *Endpoint) Open(i Identifier, typ string, reliable bool) (*Channel, error) {
	x, err := e.Dial(i)
	if err != nil {
		return nil, err
	}

	return x.Open(typ, reliable)
}

func (c *Channel) WritePacket(pkt *lob.Packet) error {
	return c.WritePacketTo(pkt, nil)
}

func (c *Channel) WritePacketTo(pkt *lob.Packet, path transports.Addr) error {
	if c == nil {
		return os.ErrInvalid
	}

	c.mtx.Lock()
	for c.blockWrite() {
		c.cndWrite.Wait()
	}

	err := c.write(pkt, path)

	if !c.blockWrite() {
		c.cndWrite.Signal()
	}
	if !c.blockRead() {
		c.cndRead.Signal()
	}

	c.mtx.Unlock()
	return err
}

func (c *Channel) blockWrite() bool {
	if c.writeDeadlineReached {
		// Never block when the write deadline is reached
		return false
	}

	if c.serverside && c.iSeq == cBlankSeq {
		// When a server channel did not (yet) read an initial packet
		// then all writes must be deferred.
		return true
	}

	if !c.serverside && (c.iSeq == cBlankSeq && c.oAckedSeq == cBlankSeq) && c.oSeq >= cInitialSeq {
		// When a client channel sent a packet but did not yet read a response
		// to the initial packet then subsequent writes must be deferred.
		return true
	}

	if len(c.writeBuffer) >= cWriteBufferSize {
		// When a channel filled its write buffer then
		// all writes must be deferred.
		return true
	}

	return false
}

func (c *Channel) write(pkt *lob.Packet, path transports.Addr) error {
	if c.broken {
		// When a channel is marked as broken the all writes
		// must return a BrokenChannelError.
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	if c.writeDeadlineReached {
		// When a channel reached a write deadline then all writes
		// must return a ErrTimeout.
		return ErrTimeout
	}

	if c.deliveredEnd {
		// When a channel sent a packet with the "end" header set
		// then all subsequent writes must return io.EOF
		return io.EOF
	}

	c.oSeq++
	hdr := pkt.Header()
	hdr.C, hdr.HasC = c.id, true
	if c.reliable {
		hdr.Seq, hdr.HasSeq = c.oSeq, true
	}
	if !c.serverside && c.oSeq == cInitialSeq {
		hdr.Type, hdr.HasType = c.typ, true
	}

	end := hdr.HasEnd && hdr.End
	if end {
		c.deliveredEnd = true
		c.setCloseDeadline()
	}

	if c.reliable {
		if c.oSeq%30 == 0 {
			c.applyAckHeaders(pkt)
		}
		c.writeBuffer[c.oSeq] = &writeBufferEntry{pkt, end, time.Time{}, path}
		c.needsResend = false
	}

	err := c.x.deliverPacket(pkt, path)
	if err != nil {
		return err
	}
	statChannelSndPkt.Add(1)
	if pkt.Header().HasAck {
		statChannelSndAckInline.Add(1)
	}

	if c.oSeq == cInitialSeq && c.serverside {
		c.unsetOpenDeadline()
	}

	return nil
}

func (c *Channel) ReadPacket() (*lob.Packet, error) {
	if c == nil {
		return nil, os.ErrInvalid
	}

	c.mtx.Lock()
	for c.blockRead() {
		c.cndRead.Wait()
	}

	pkt, err := c.peekPacket()
	if pkt != nil {
		c.readPacket()
	}

	c.mtx.Unlock()
	return pkt, err
}

func (c *Channel) blockRead() bool {
	if c.broken {
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		return false
	}

	if c.readDeadlineReached {
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		return false
	}

	if c.readEnd {
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		return false
	}

	if c.serverside && c.oSeq == cBlankSeq && c.iSeq >= cInitialSeq {
		// When a server channel read a packet but did not yet respond
		// to the initial packet then subsequent reads must be deferred.
		return true
	}

	if !c.serverside && c.oSeq == cBlankSeq {
		// When a client channel did not (yet) send an initial packet
		// then all reads must be deferred.
		return true
	}

	rSeq := c.iSeq + 1
	if len(c.readBuffer) == 0 || c.readBuffer[0].seq != rSeq {
		// Packet has not yet been received
		// defer the read
		return true
	}

	return false
}

func (c *Channel) peekPacket() (*lob.Packet, error) {
	if c.broken {
		// When a channel is marked as broken the all reads
		// must return a BrokenChannelError.
		return nil, &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	if c.readDeadlineReached {
		// When a channel reached a read deadline then all reads
		// must return a ErrTimeout.
		return nil, ErrTimeout
	}

	if c.readEnd {
		// When a channel read a packet with the "end" header set
		// then all subsequent reads must return io.EOF
		return nil, io.EOF
	}

	e := c.readBuffer[0]

	{ // clean headers
		h := e.pkt.Header()
		h.HasAck = false
		h.HasC = false
		h.HasMiss = false
		h.HasSeq = false
		h.HasType = false
		h.HasEnd = false
	}

	if len(e.pkt.Body) == 0 && e.pkt.Header().IsZero() && e.end {
		// read empty `end` packet
		c.readPacket()
		return nil, io.EOF
	}

	return e.pkt, nil
}

func (c *Channel) readPacket() {
	rSeq := c.iSeq + 1
	e := c.readBuffer[0]

	c.iSeq = rSeq

	// remove entry
	copy(c.readBuffer, c.readBuffer[1:])
	c.readBuffer = c.readBuffer[:len(c.readBuffer)-1]

	if e.end {
		c.deliverAck()
		c.readEnd = true
	}

	if c.iSeq == cInitialSeq && !c.serverside {
		c.unsetOpenDeadline()
	}

	c.maybeDeliverAdHocAck()

	if c.deliveredEnd && !c.blockClose() {
		c.cndClose.Signal()
	}
	if !c.blockRead() {
		c.cndRead.Signal()
	}
	if !c.blockWrite() {
		c.cndWrite.Signal()
	}
}

func (c *Channel) receivedPacket(pkt *lob.Packet) {
	c.mtx.Lock()

	if c.broken {
		c.mtx.Unlock()
		statChannelRcvPktDrop.Add(1)
		return
	}

	var (
		hdr           = pkt.Header()
		seq, hasSeq   = hdr.Seq, hdr.HasSeq
		ack, hasAck   = hdr.Ack, hdr.HasAck
		miss, hasMiss = hdr.Miss, hdr.HasMiss
		end, hasEnd   = hdr.End, hdr.HasEnd
	)

	if !c.reliable {
		// unreliable channels (internaly) emulate reliable channels.
		seq = c.iBufferedSeq + 1
		hasSeq = true

	} else {
		// determine what to drop from the write buffer
		if hasAck {
			if hasSeq {
				statChannelRcvAckInline.Add(1)
			} else {
				statChannelRcvAckAdHoc.Add(1)
			}

			var (
				oldAck  = c.oAckedSeq
				changed bool
			)

			if c.oAckedSeq < ack {
				c.oAckedSeq = ack
				changed = true
			}

			for i := oldAck + 1; i <= ack; i++ {
				delete(c.writeBuffer, i)
				changed = true
			}

			if len(c.writeBuffer) == 0 {
				c.needsResend = false
			}

			if changed {
				c.cndWrite.Signal()
				if c.deliveredEnd || c.receivedEnd {
					c.cndClose.Signal()
				}
			}

			if hasMiss {
				c.processMissingPackets(ack, miss)
			}
		}
	}

	if !hasSeq {
		// drop: is not a valid packet
		c.mtx.Unlock()

		if !hasAck {
			statChannelRcvPktDrop.Add(1)
		}

		return
	}

	if c.reliable && c.iSeenSeq < seq {
		// record highest seen seq
		c.iSeenSeq = seq
	}

	if seq <= c.iSeq {
		// drop: the reader already read a packet with this seq
		c.mtx.Unlock()
		statChannelRcvPktDrop.Add(1)
		return
	}

	if len(c.readBuffer) >= cReadBufferSize {
		// drop: the read buffer is full
		c.mtx.Unlock()
		statChannelRcvPktDrop.Add(1)
		return
	}

	if c.readBuffer.IndexOf(seq) >= 0 {
		// drop: a packet with this seq is already buffered
		c.mtx.Unlock()
		statChannelRcvPktDrop.Add(1)
		return
	}

	if c.iBufferedSeq < seq {
		c.iBufferedSeq = seq
	}
	if end && hasEnd {
		c.receivedEnd = true
		c.deliverAck()
	}

	c.readBuffer = append(c.readBuffer, &readBufferEntry{pkt, seq, end})
	sort.Sort(c.readBuffer)

	c.cndRead.Signal()
	c.mtx.Unlock()
	statChannelRcvPkt.Add(1)
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
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		c.mtx.Unlock()
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	for c.blockWrite() {
		c.cndWrite.Wait()
	}

	if c.deliveredEnd {
		c.mtx.Unlock()
		return nil
	}

	pkt := &lob.Packet{}
	pkt.Header().SetString("err", err.Error())
	if err := c.write(pkt, nil); err != nil {
		c.mtx.Unlock()
		return err
	}

	c.broken = true
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregisterChannel(c.id)
	c.mtx.Unlock()
	return nil
}

func (c *Channel) Close() error {
	if c == nil {
		return os.ErrInvalid
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.broken {
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	c.setCloseDeadline()

	if !c.deliveredEnd {
		for c.blockWrite() {
			c.cndWrite.Wait()
		}

		if !c.deliveredEnd {
			pkt := &lob.Packet{}
			hdr := pkt.Header()
			hdr.End, hdr.HasEnd = true, true
			if err := c.write(pkt, nil); err != nil {
				return err
			}
		}
	}

	for {
		for c.blockRead() {
			c.cndRead.Wait()
		}
		pkt, err := c.peekPacket()
		if pkt != nil {
			c.readPacket()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	for c.blockClose() {
		c.cndClose.Wait()
	}

	if c.broken {
		// When a channel is marked as broken the all closes
		// must return a BrokenChannelError.
		return &BrokenChannelError{c.hashname, c.typ, c.id}
	}

	c.unsetTimers()

	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregisterChannel(c.id)
	return nil
}

func (c *Channel) blockClose() bool {
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
	// c.iSeq last read packet
	// c.iSeq+1 is the next packet to be read
	// c.iSeenSeq is the highest seq sean.
	// c.iSeq + cReadBufferSize must be the last seq in the miss list

	var (
		miss []uint32
		last = c.iSeq
		n    int
		seq  uint32 = c.iSeq + 1
	)

	for _, e := range c.readBuffer {
		if seq == e.seq {
			seq++
			continue
		}

		for seq < e.seq {
			if miss == nil {
				miss = make([]uint32, 0, cReadBufferSize)
			}
			miss = append(miss, seq-last)
			last = seq
			seq++

			n++
			if n >= (cReadBufferSize - 1) {
				goto ADD_HIGHEST_ACCEPTABLE_SEQ
			}
		}
	}

	for seq <= c.iSeenSeq {
		if miss == nil {
			miss = make([]uint32, 0, cReadBufferSize)
		}
		miss = append(miss, seq-last)
		last = seq
		seq++

		n++
		if n >= (cReadBufferSize - 1) {
			goto ADD_HIGHEST_ACCEPTABLE_SEQ
		}
	}

ADD_HIGHEST_ACCEPTABLE_SEQ:
	if n > 0 {
		miss = append(miss, (c.iSeq+cReadBufferSize)-last)
	}

	return miss
}

func (c *Channel) processMissingPackets(ack uint32, miss []uint32) {
	var (
		omiss     = c.buildMissList()
		now       = time.Now()
		oneSecAgo = now.Add(-1 * time.Second)
		last      = ack
	)

	for _, delta := range miss {
		seq := last + delta
		last = seq

		e, f := c.writeBuffer[seq]
		if !f || e == nil {
			continue
		}

		if e.lastResend.After(oneSecAgo) {
			continue
		}

		hdr := e.pkt.Header()
		if c.iSeq >= cInitialSeq {
			hdr.Ack, hdr.HasAck = c.iSeq, true
		}
		if len(omiss) > 0 {
			hdr.Miss, hdr.HasMiss = omiss, true
		}
		e.lastResend = now

		err := c.x.deliverPacket(e.pkt, e.dst)
		if err == nil {
			statChannelSndPkt.Add(1)
		}
	}
}

func (c *Channel) resendLastPacket() {
	c.mtx.Lock()

	var needsResend bool
	needsResend, c.needsResend = c.needsResend, true
	c.tResend.Reset(1 * time.Second)

	if !needsResend {
		c.mtx.Unlock()
		return
	}

	e := c.writeBuffer[c.oSeq]
	if e == nil {
		c.mtx.Unlock()
		return
	}

	omiss := c.buildMissList()
	hdr := e.pkt.Header()
	if c.iSeq >= cInitialSeq {
		hdr.Ack, hdr.HasAck = c.iSeq, true
	}
	if len(omiss) > 0 {
		hdr.Miss, hdr.HasMiss = omiss, true
	}
	e.lastResend = time.Now()
	c.mtx.Unlock()

	err := c.x.deliverPacket(e.pkt, e.dst)
	if err == nil {
		statChannelSndPkt.Add(1)
	}
}

func (c *Channel) maybeDeliverAdHocAck() {
	if !c.reliable {
		return
	}

	if c.iSeq < cInitialSeq {
		return // nothing to ack
	}

	if c.iSeq-c.iAckedSeq >= earlyAdHocAck {
		c.deliverAck()
	}
}

func (c *Channel) autoDeliverAck() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.deliverAck()
	c.tAcker.Reset(10 * time.Second)
}

func (c *Channel) deliverAck() {
	if !c.reliable {
		return
	}

	pkt := &lob.Packet{}
	hdr := pkt.Header()
	hdr.C, hdr.HasC = c.id, true
	c.applyAckHeaders(pkt)
	err := c.x.deliverPacket(pkt, nil)
	if err == nil {
		statChannelSndAckAdHoc.Add(1)
	}
}

func (c *Channel) applyAckHeaders(pkt *lob.Packet) {
	if !c.reliable {
		return
	}

	if c.iSeq == cBlankSeq {
		// nothin to ack
		return
	}

	hdr := pkt.Header()
	if c.iSeq >= cInitialSeq {
		hdr.Ack, hdr.HasAck = c.iSeq, true
	}
	if l := c.buildMissList(); len(l) > 0 {
		hdr.Miss, hdr.HasMiss = l, true
	}

	c.iAckedSeq = c.iSeq
}

func (c *Channel) setCloseDeadline() {
	if c.tCloseDeadline == nil {
		if c.closeDeadlineReached {
			return
		}

		c.tCloseDeadline = time.AfterFunc(
			60*time.Second,
			c.onCloseDeadlineReached,
		)
	}
}

func (c *Channel) onCloseDeadlineReached() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.broken = true
	c.closeDeadlineReached = true
	c.unsetOpenDeadline()
	c.unsetCloseDeadline()
	c.unsetResender()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregisterChannel(c.id)
}

func (c *Channel) setOpenDeadline() {
	if c.tOpenDeadline == nil {
		if c.openDeadlineReached {
			return
		}

		c.tOpenDeadline = time.AfterFunc(
			60*time.Second,
			c.onOpenDeadlineReached,
		)
	}
}

func (c *Channel) unsetTimers() {
	c.unsetOpenDeadline()
	c.unsetCloseDeadline()
	c.unsetReadDeadline()
	c.unsetWriteDeadline()
	c.unsetResender()
	c.unsetAcker()
}

func (c *Channel) unsetReadDeadline() {
	if c.tReadDeadline != nil {
		c.tReadDeadline.Stop()
	}
}

func (c *Channel) unsetWriteDeadline() {
	if c.tWriteDeadline != nil {
		c.tWriteDeadline.Stop()
	}
}

func (c *Channel) unsetOpenDeadline() {
	if c.tOpenDeadline != nil {
		c.tOpenDeadline.Stop()
	}
}

func (c *Channel) unsetCloseDeadline() {
	if c.tCloseDeadline != nil {
		c.tCloseDeadline.Stop()
	}
}

func (c *Channel) unsetResender() {
	if c.tResend != nil {
		c.tResend.Stop()
	}
}

func (c *Channel) unsetAcker() {
	if c.tAcker != nil {
		c.tAcker.Stop()
	}
}

func (c *Channel) onOpenDeadlineReached() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.broken = true
	c.openDeadlineReached = true
	c.unsetTimers()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregisterChannel(c.id)
}

func (c *Channel) forget() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.broken = true
	c.openDeadlineReached = false
	c.unsetTimers()

	// broadcast
	c.cndWrite.Broadcast()
	c.cndRead.Broadcast()
	c.cndClose.Broadcast()

	c.x.unregisterChannel(c.id)
}

// Read implements the net.Conn Read method.
func (c *Channel) Read(b []byte) (int, error) {
	pkt, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}

	n := len(pkt.Body)
	if len(b) < n {
		return 0, io.ErrShortBuffer
	}

	copy(b, pkt.Body)
	pkt.Free()

	return n, nil
}

// Write implements the net.Conn Write method.
func (c *Channel) Write(b []byte) (int, error) {
	n := len(b)
	pkt := &lob.Packet{Body: bufpool.GetBuffer()[:n]}
	copy(pkt.Body, b)

	err := c.WritePacket(pkt)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// SetDeadline implements the net.Conn SetDeadline method.
func (c *Channel) SetDeadline(d time.Time) error {
	c.mtx.Lock()

	now := time.Now()

	if d.IsZero() {
		c.tReadDeadline.Stop()
		c.readDeadlineReached = false
		c.tWriteDeadline.Stop()
		c.writeDeadlineReached = false
	} else if d.Before(now) {
		c.tReadDeadline.Stop()
		c.readDeadlineReached = true
		c.tWriteDeadline.Stop()
		c.writeDeadlineReached = true
	} else {
		c.tReadDeadline.Reset(d.Sub(now))
		c.readDeadlineReached = false
		c.tWriteDeadline.Reset(d.Sub(now))
		c.writeDeadlineReached = false
	}

	c.cndClose.Broadcast()
	c.cndRead.Broadcast()
	c.cndWrite.Broadcast()

	c.mtx.Unlock()
	return nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *Channel) SetReadDeadline(d time.Time) error {
	c.mtx.Lock()

	now := time.Now()

	if d.IsZero() {
		c.tReadDeadline.Stop()
		c.readDeadlineReached = false
	} else if d.Before(now) {
		c.tReadDeadline.Stop()
		c.readDeadlineReached = true
	} else {
		c.tReadDeadline.Reset(d.Sub(now))
		c.readDeadlineReached = false
	}

	c.cndClose.Broadcast()
	c.cndRead.Broadcast()

	c.mtx.Unlock()
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (c *Channel) SetWriteDeadline(d time.Time) error {
	c.mtx.Lock()

	now := time.Now()

	if d.IsZero() {
		c.tWriteDeadline.Stop()
		c.writeDeadlineReached = false
	} else if d.Before(now) {
		c.tWriteDeadline.Stop()
		c.writeDeadlineReached = true
	} else {
		c.tWriteDeadline.Reset(d.Sub(now))
		c.writeDeadlineReached = false
	}

	c.cndClose.Broadcast()
	c.cndWrite.Broadcast()

	c.mtx.Unlock()
	return nil
}

func (c *Channel) onReadDeadlineReached() {
	c.mtx.Lock()

	c.readDeadlineReached = true

	c.cndClose.Broadcast()
	c.cndRead.Broadcast()

	c.mtx.Unlock()
}

func (c *Channel) onWriteDeadlineReached() {
	c.mtx.Lock()

	c.writeDeadlineReached = true

	c.cndClose.Broadcast()
	c.cndWrite.Broadcast()

	c.mtx.Unlock()
}

// LocalAddr returns the local network address.
func (c *Channel) LocalAddr() net.Addr {
	return c.Exchange().localIdent.Hashname()
}

// RemoteAddr returns the remote network address.
func (c *Channel) RemoteAddr() net.Addr {
	return c.RemoteHashname()
}

type readBufferSlice []*readBufferEntry

func (s readBufferSlice) Len() int           { return len(s) }
func (s readBufferSlice) Less(i, j int) bool { return s[i].seq < s[j].seq }
func (s readBufferSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s readBufferSlice) IndexOf(seq uint32) int {
	l := len(s)
	idx := sort.Search(l, func(i int) bool { return s[i].seq >= seq })
	if idx == l {
		return -1
	}
	return idx
}
