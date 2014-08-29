package e3x

import (
  "io"

  "bitbucket.org/simonmenke/go-telehash/hashname"
  "bitbucket.org/simonmenke/go-telehash/lob"
)

const (
  c_READ_BUFFER_SIZE  = 100
  c_WRITE_BUFFER_SIZE = 100
)

type channelState struct {
  serverside bool
  id         uint32
  typ        string
  hashname   hashname.H
  reliable   bool
  broken     bool

  qRead    []*resReadPacket
  qDeliver []*resDeliverPacket

  oSeq         int // highest seq in write stream
  iBufferedSeq int // highest buffered seq in read stream
  iSeq         int // highest seq in read stream
  oAckedSeq    int // highest acked seq in write stream
  iAckedSeq    int // highest acked seq in read stream

  deliveredEnd         bool
  receivedEnd          bool
  readEnd              bool
  writeDeadlineReached bool
  readDeadlineReached  bool
  readBuffer           map[uint32]*readBufferEntry
  writeBuffer          map[uint32]*writeBufferEntry
}

func resolvedWaitChan() chan struct{} {
  c := make(chan struct{}, 1)
  c <- struct{}{}
  return c
}

func unresolvedWaitChan() chan struct{} {
  return make(chan struct{})
}

type resDeliverPacket struct {
  err   error
  cWait chan struct{}
}

func (r *resDeliverPacket) deferred() bool {
  return cap(r.cWait) == 0
}

func (r *resDeliverPacket) resolve(err error) {
  r.err = err
  r.cWait <- struct{}{}
}

func (r *resDeliverPacket) wait() error {
  <-r.cWait
  return r.err
}

type resReadPacket struct {
  pkt   *lob.Packet
  err   error
  cWait chan struct{}
}

func (r *resReadPacket) deferred() bool {
  return cap(r.cWait) == 0
}

func (r *resReadPacket) resolve(pkt *lob.Packet, err error) {
  r.pkt = pkt
  r.err = err
  r.cWait <- struct{}{}
}

func (r *resReadPacket) wait() (*lob.Packet, error) {
  <-r.cWait
  return r.pkt, r.err
}

func newChannelState(hn hashname.H, typ string, id uint32, reliable bool, serverside bool) *channelState {
  return &channelState{
    hashname:     hn,
    typ:          typ,
    id:           id,
    reliable:     reliable,
    serverside:   serverside,
    readBuffer:   make(map[uint32]*readBufferEntry, 100),
    writeBuffer:  make(map[uint32]*writeBufferEntry, 100),
    oSeq:         -1,
    iBufferedSeq: -1,
    iSeq:         -1,
    oAckedSeq:    -1,
    iAckedSeq:    -1,
  }
}

func (c *channelState) DeliverPacket(pkt *lob.Packet) (*lob.Packet, error) {
  c.oSeq++
  pkt.Header().SetUint32("c", c.id)
  if c.reliable {
    pkt.Header().SetUint32("seq", uint32(c.oSeq))
  }
  if !c.serverside && c.oSeq == 0 {
    pkt.Header().SetString("type", c.typ)
  }
  return pkt, nil
}

func (c *channelState) ReceivePacket(pkt *lob.Packet) {
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

      for i := oldAck; i < int(ack); i++ {
        delete(c.writeBuffer, uint32(i))
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

  if int(seq) <= c.iSeq {
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

  if c.iBufferedSeq < int(seq) {
    c.iBufferedSeq = int(seq)
  }
  if end && hasEnd {
    c.receivedEnd = end
  }

  c.readBuffer[seq] = &readBufferEntry{pkt, seq, end}
}

func (c *channelState) ReadPacket() *resReadPacket {
  if c.broken {
    // When a channel is marked as broken the all reads
    // must return a BrokenChannelError.
    return &resReadPacket{
      pkt:   nil,
      err:   &BrokenChannelError{c.hashname, c.typ, c.id},
      cWait: resolvedWaitChan(),
    }
  }

  if c.readDeadlineReached {
    // When a channel reached a read deadline then all reads
    // must return a ErrTimeout.
    return &resReadPacket{
      pkt:   nil,
      err:   ErrTimeout,
      cWait: resolvedWaitChan(),
    }
  }

  if c.readEnd {
    // When a channel read a packet with the "end" header set
    // then all subsequent reads must return io.EOF
    return &resReadPacket{
      pkt:   nil,
      err:   io.EOF,
      cWait: resolvedWaitChan(),
    }
  }

  if c.serverside && c.oSeq == -1 && c.iSeq >= 0 {
    // When a server channel read a packet but did not yet respond
    // to the initial packet then subsequent reads must be deferred.
    promise := &resReadPacket{cWait: unresolvedWaitChan()}
    c.qRead = append(c.qRead, promise)
    return promise
  }

  if !c.serverside && c.oSeq == -1 {
    // When a client channel did not (yet) send an initial packet
    // then all reads must be deferred.
    promise := &resReadPacket{cWait: unresolvedWaitChan()}
    c.qRead = append(c.qRead, promise)
    return promise
  }

  rSeq := uint32(c.iSeq + 1)
  e := c.readBuffer[rSeq]
  if e == nil {
    // Packet has not yet been received
    // defer the read
    promise := &resReadPacket{cWait: unresolvedWaitChan()}
    c.qRead = append(c.qRead, promise)
    return promise
  }

  c.iSeq = int(rSeq)
  delete(c.readBuffer, rSeq)

  if e.end {
    c.readEnd = e.end
  }

  return &resReadPacket{
    pkt:   e.pkt,
    err:   nil,
    cWait: resolvedWaitChan(),
  }
}

func (c *channelState) Break() {
  c.broken = true
}

func (c *channelState) ReachedReadDeadline() {
  c.readDeadlineReached = true
}

func (c *channelState) ReachedWriteDeadline() {
  c.writeDeadlineReached = true
}

func (c *channelState) State() ChannelState {
  if c.broken {
    return BrokenChannelState
  }

  if c.readEnd || c.deliveredEnd {
    return EndedChannelState
  }

  if c.iSeq >= 0 && c.oSeq >= 0 {
    return OpenChannelState
  }

  return OpeningChannelState
}

func (c *channelState) deferWrite() bool {
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

  if c.serverside && c.iSeq == -1 {
    // When a server channel did not (yet) read an initial packet
    // then all writes must be deferred.
    return true
  }

  if !c.serverside && c.iSeq == -1 && c.oSeq >= 0 {
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
  end    bool
  inMiss bool
}
