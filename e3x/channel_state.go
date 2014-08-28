package e3x

import (
	"container/heap"

	"bitbucket.org/simonmenke/go-telehash/lob"
)

const (
	c_READ_BUFFER_SIZE  = 100
	c_WRITE_BUFFER_SIZE = 100
)

type channelFSM struct {
	isServer             bool
	deliverdPacketCount  uint64
	ackedPacketCount     uint64
	receivedPacketCount  uint64
	readPacketCount      uint64
	deliveredEnd         bool
	receivedEnd          bool
	readEnd              bool
	broken               bool
	writeDeadlineReached bool
	readDeadlineReached  bool
}

func (c *channelFSM) DeliveredPacket(end bool) {
	c.deliverdPacketCount++
	if end {
		c.deliveredEnd = end
	}
}

func (c *channelFSM) AckedPacket() {
	c.ackedPacketCount++
}

func (c *channelFSM) ReceivedPacket(end bool) {
	c.receivedPacketCount++
	if end {
		c.receivedEnd = end
	}
}

func (c *channelFSM) ReadPacket(end bool) {
	c.readPacketCount++
	if end {
		c.readEnd = end
	}
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

	if c.readPacketCount > 0 && c.deliverdPacketCount > 0 {
		return OpenChannelState
	}

	return OpeningChannelState
}

func (c *channelFSM) deferRead() bool {
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

	if c.isServer && c.deliverdPacketCount == 0 && c.readPacketCount > 0 {
		// When a server channel read a packet but did not yet respond
		// to the initial packet then subsequent reads must be deferred.
		return true
	}

	if !c.isServer && c.deliverdPacketCount == 0 {
		// When a client channel did not (yet) send an initial packet
		// then all reads must be deferred.
		return true
	}

	if c.receivedPacketCount == c.readPacketCount {
		// When a channel read as many packets as it received then
		// all reads must be deferred.
		return true
	}

	// Otherwise there must be a received packet available.
	return false
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

	if c.isServer && c.readPacketCount == 0 {
		// When a server channel did not (yet) read an initial packet
		// then all writes must be deferred.
		return true
	}

	if !c.isServer && c.readPacketCount == 0 && c.deliverdPacketCount > 0 {
		// When a client channel sent a packet but did not yet read a response
		// to the initial packet then subsequent writes must be deferred.
		return true
	}

	if c.deliverdPacketCount-c.ackedPacketCount >= c_WRITE_BUFFER_SIZE {
		// When a channel filled it write buffer then
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

type readBuffer []readBufferEntry

func (b readBuffer) Len() int {
	return len(b)
}

func (b readBuffer) Less(i, j int) bool {
	return b[i].seq < b[j].seq
}

func (b readBuffer) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b *readBuffer) Push(x interface{}) {
	*b = append(*b, x.(readBufferEntry))
}

func (b *readBuffer) Pop() interface{} {
	old := *b
	l := len(old)
	x := old[l-1]
	*b = old[:l-1]
	return x
}
