package e3x

import (
  "errors"
  "fmt"
  "io"
  "time"

  "bitbucket.org/simonmenke/go-telehash/hashname"
  "bitbucket.org/simonmenke/go-telehash/lob"
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

type Channel struct {
  state               ChannelState
  hashname            hashname.H
  id                  uint32
  typ                 string
  reliable            bool
  isServer            bool
  exchange            *exchange
  endpoint            *Endpoint
  tReadDeadline       *scheduler.Event
  tOpenDeadline       *scheduler.Event
  openPktSent         bool
  openPktRead         bool
  readDeadlineReached bool
  readablePacket      *lob.Packet
  nextSeq             uint32
  qDeliver            []*opDeliverPacket
  qReceive            []*opReceivePacket
}

type opRegisterChannel struct {
  ch   *Channel
  cErr chan error
}

type opDeliverPacket struct {
  ch   *Channel
  pkt  *lob.Packet
  cErr chan error
}

type opReceivePacket struct {
  ch   *Channel
  pkt  *lob.Packet
  cErr chan error
}

func newChannel(hn hashname.H, typ string, reliable bool, e *Endpoint) *Channel {
  c := &Channel{
    hashname: hn,
    typ:      typ,
    reliable: reliable,
    endpoint: e,
  }

  c.tReadDeadline = e.scheduler.NewEvent(c.on_read_deadline_reached)
  c.tOpenDeadline = e.scheduler.NewEvent(c.on_open_deadline_reached)

  return c
}

func (e *Endpoint) Dial(addr *Addr, typ string, reliable bool) (*Channel, error) {
  ch := newChannel(addr.hashname, typ, reliable, e)

  err := e.DialExchange(addr)
  if err != nil {
    return nil, err
  }

  { // register channel
    op := opRegisterChannel{ch: ch, cErr: make(chan error)}
    e.cRegisterChannel <- &op
    err := <-op.cErr
    if err != nil {
      return nil, err
    }
  }

  ch.tOpenDeadline.ScheduleAfter(60 * time.Second)

  return ch, nil
}

func (c *Channel) on_read_deadline_reached() {
  c.readDeadlineReached = true
}

func (c *Channel) on_open_deadline_reached() {
  c.state = BrokenChannelState
}

// BUG(fd) needs reliable support
func (c *Channel) received_packet(pkt *lob.Packet) {

  if c.state == OpeningChannelState {
    c.tOpenDeadline.Cancel()
    c.tOpenDeadline = nil
    c.state = OpenChannelState
  }

  if c.readablePacket != nil {
    // drop pkt
    return
  }

  c.readablePacket = pkt
}

func (c *Channel) WritePacket(pkt *lob.Packet) error {
  op := opDeliverPacket{ch: c, pkt: pkt, cErr: make(chan error)}
  c.endpoint.cDeliverPacket <- &op
  return waitForError(op.cErr)
}

func (c *Channel) ReadPacket() (*lob.Packet, error) {
  op := opReceivePacket{ch: c, cErr: make(chan error)}
  c.endpoint.cReceivePacket <- &op
  return op.pkt, waitForError(op.cErr)
}

func (c *Channel) deliver_packet(op *opDeliverPacket) error {
  var (
    pkt = op.pkt
  )

  if c.state == BrokenChannelState {
    return &BrokenChannelError{c.hashname, c.typ, c.id}
  }

  if c.state == EndedChannelState {
    return io.EOF
  }

  if c.isServer && c.state == OpeningChannelState && !c.openPktRead {
    c.qDeliver = append(c.qDeliver, op)
    return errDeferred
  }

  if !c.isServer && c.state == OpeningChannelState && !c.openPktSent {
    c.qDeliver = append(c.qDeliver, op)
    return errDeferred
  }

  if c.reliable && false /* write buffer is full */ {
    c.qDeliver = append(c.qDeliver, op)
    return errDeferred
  }

  pkt.Header().SetUint32("c", c.id)

  if c.reliable {
    pkt.Header().SetUint32("seq", c.nextSeq)
    c.nextSeq++
    // add to write buffer
  }

  if !c.isServer && !c.openPktSent {
    pkt.Header().Set("type", c.typ)
    c.openPktSent = true
  }

  if c.isServer && c.openPktRead && c.state == OpeningChannelState {
    c.state = OpenChannelState
  }

  c.exchange.deliver_packet(pkt)
  return nil
}

func (c *Channel) receive_packet(op *opReceivePacket) error {

  if c.state == BrokenChannelState {
    return &BrokenChannelError{c.hashname, c.typ, c.id}
  }

  if c.readDeadlineReached {
    return ErrTimeout
  }

  if c.isServer && c.state == OpeningChannelState && c.openPktRead {
    c.qReceive = append(c.qReceive, op)
    return errDeferred
  }

  if !c.isServer && c.state == OpeningChannelState {
    c.qReceive = append(c.qReceive, op)
    return errDeferred
  }

  if c.readablePacket == nil {
    if c.state == EndedChannelState {
      return io.EOF
    }

    c.qReceive = append(c.qReceive, op)
    return errDeferred
  }

  op.pkt = c.readablePacket
  c.readablePacket = nil

  if c.isServer && !c.openPktRead {
    c.openPktRead = true
  }

  if !c.isServer && c.state == OpeningChannelState && c.openPktSent {
    c.state = OpenChannelState
  }

  return nil
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

  ch.id = x.nextChannelId()
  ch.exchange = x
  x.channels[ch.id] = ch

  if wasIdle {
    x.tExpire.Cancel()
  }

  return nil
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
