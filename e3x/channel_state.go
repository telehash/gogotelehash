package e3x

import (
	"bitbucket.org/simonmenke/go-telehash/lob"
)

const (
	c_READ_BUFFER_SIZE  = 100
	c_WRITE_BUFFER_SIZE = 100
)

type channelFSM struct {
	isServer            bool
	reliable            bool
	deliverdPacketCount uint64
	// ackedPacketCount     uint64
	// receivedPacketCount  uint64
	// readPacketCount      uint64
	deliverdSeq          uint32
	ackedSeq             uint32
	receivedSeq          uint32
	readSeq              uint32
	nextReadSeq          uint32
	deliveredEnd         bool
	receivedEnd          bool
	readEnd              bool
	broken               bool
	writeDeadlineReached bool
	readDeadlineReached  bool
	readBuffer           map[uint32]*readBufferEntry
	writeBuffer          map[uint32]*writeBufferEntry
}

func (c *channelFSM) DeliveredPacket(end bool) {
	c.deliverdPacketCount++
	if end {
		c.deliveredEnd = end
	}
}

func (c *channelFSM) ReceivedPacket(pkt *lob.Packet) {
	var (
		seq, hasSeq   = pkt.Header().GetUint32("seq")
		ack, hasAck   = pkt.Header().GetUint32("ack")
		miss, hasMiss = pkt.Header().GetUint32Slice("miss")
		end, hasEnd   = pkt.Header().GetBool("end")
	)

	if !c.reliable {
		// unreliable channels (internaly) emulate reliable channels.
		seq = c.receivedSeq + 1
		hasSeq = true

	} else {
		// determine what to drop from the write buffer
		if hasAck {
			var (
				oldAck = c.ackedSeq
			)

			if c.ackedSeq < ack {
				c.ackedSeq = ack
			}

			for i := oldAck; i < ack; i++ {
				delete(c.writeBuffer, i)
			}
		}

		if hasMiss {
			for _, e := range c.writeBuffer {
				e.inMiss = false
			}

			for _, seq := range miss {
				if p, f := c.writeBuffer[seq]; f && p != nil {
					p.inMiss = true
				}
			}

			for k, e := range c.writeBuffer {
				if e.inMiss == false {
					delete(c.writeBuffer, k)
				}
			}
		}
	}

	if !hasSeq {
		// drop: is not a valid packet
		return
	}

	if seq <= c.readSeq {
		// drop: the reader already read a packet with this seq
		return
	}

	if _, found := c.readBuffer[seq]; found {
		// drop: a packet with this seq is already buffered
		return
	}

	if len(c.readBuffer) > c_READ_BUFFER_SIZE {
		// drop: the read buffer is full
		return
	}

	if c.receivedSeq < seq {
		c.receivedSeq = seq
	}
	if end && hasEnd {
		c.receivedEnd = end
	}

	c.readBuffer[seq] = &readBufferEntry{pkt, seq, end}
}

func (c *channelFSM) ReadPacket() (*lob.Packet, error) {
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

	if c.isServer && c.deliverdPacketCount == 0 && c.nextReadSeq > 0 {
		// When a server channel read a packet but did not yet respond
		// to the initial packet then subsequent reads must be deferred.
		return nil, errDeferred
	}

	if !c.isServer && c.deliverdPacketCount == 0 {
		// When a client channel did not (yet) send an initial packet
		// then all reads must be deferred.
		return nil, errDeferred
	}

	e := c.readBuffer[c.nextReadSeq]
	if e == nil {
		// Packet has not yet been received
		// defer the read
		return nil, errDeferred
	}

	c.readSeq = e.seq
	c.nextReadSeq++
	delete(c.readBuffer, e.seq)

	if e.end {
		c.readEnd = e.end
	}

	return e.pkt, nil
}

func (c *channelFSM) Break() {
	c.broken = true
}

func (c *channelFSM) ReachedReadDeadline() {
	c.readDeadlineReached = true
}

func (c *channelFSM) ReachedWriteDeadline() {
	c.writeDeadlineReached = true
}

func (c *channelFSM) State() ChannelState {
	if c.broken {
		return BrokenChannelState
	}

	if c.readEnd || c.deliveredEnd {
		return EndedChannelState
	}

	if c.readSeq > 0 && c.deliverdPacketCount > 0 {
		return OpenChannelState
	}

	return OpeningChannelState
}

func (c *channelFSM) deferWrite() bool {
	if c.broken {
		// When a channel is marked as broken the all writes
		// must return a BrokenChannelError.
		return false
	}

	if c.writeDeadlineReached {
		// When a channel reached a write deadline then all writes
		// must return a ErrTimeout.
		return false
	}

	if c.deliveredEnd {
		// When a channel sent a packet with the "end" header set
		// then all subsequent writes must return io.EOF
		return false
	}

	if c.isServer && c.nextReadSeq == 0 {
		// When a server channel did not (yet) read an initial packet
		// then all writes must be deferred.
		return true
	}

	if !c.isServer && c.nextReadSeq == 0 && c.deliverdPacketCount > 0 {
		// When a client channel sent a packet but did not yet read a response
		// to the initial packet then subsequent writes must be deferred.
		return true
	}

	if len(c.writeBuffer) >= c_WRITE_BUFFER_SIZE {
		// When a channel filled its write buffer then
		// all writes must be deferred.
		return true
	}

	// Otherwise there packets may be delivered.
	return false
}

type readBufferEntry struct {
	pkt *lob.Packet
	seq uint32
	end bool
}

type writeBufferEntry struct {
	pkt    *lob.Packet
	seq    uint32
	end    bool
	inMiss bool
}

// type readBuffer []readBufferEntry

// func (b readBuffer) Len() int {
//   return len(b)
// }

// func (b readBuffer) Less(i, j int) bool {
//   return b[i].seq < b[j].seq
// }

// func (b readBuffer) Swap(i, j int) {
//   b[i], b[j] = b[j], b[i]
// }

// func (b *readBuffer) Push(x interface{}) {
//   *b = append(*b, x.(readBufferEntry))
// }

// func (b *readBuffer) Pop() interface{} {
//   old := *b
//   l := len(old)
//   x := old[l-1]
//   *b = old[:l-1]
//   return x
// }
