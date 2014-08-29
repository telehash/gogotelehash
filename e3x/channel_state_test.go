package e3x

import (
  "testing"

  "github.com/stretchr/testify/assert"
  "github.com/stretchr/testify/suite"

  "bitbucket.org/simonmenke/go-telehash/lob"
)

type channelStateTestSuite struct {
  suite.Suite
}

func TestChannelState(t *testing.T) {
  suite.Run(t, &channelStateTestSuite{})
}

func (s *channelStateTestSuite) Test_Client_Reliable_SingleRT() {
  var (
    assert = s.Assertions
    ch     = newChannelState("a-hashname", "ping", 1, true, false)
    pkt    *lob.Packet
    dres   *resDeliverPacket
    rres   *resReadPacket
    err    error
  )

  // in opening state
  assert.Equal(OpeningChannelState, ch.State())

  // read that happens before sending the open pkt should defer
  rres = ch.ReadPacket()
  assertDeferred(assert, rres)

  // in opening state
  assert.Equal(OpeningChannelState, ch.State())

  // deliver open packet
  pkt, err = ch.DeliverPacket(packet().body("ping 1").b())
  assert.NoError(err)
  assert.NotNil(pkt)
  assertC(assert, pkt, 1)
  assertType(assert, pkt, "ping")
  assertSeq(assert, pkt, 0)
  assertNoAck(assert, pkt)
  assertBody(assert, pkt, "ping 1")

  // in opening state
  assert.Equal(OpeningChannelState, ch.State())

  // write that happens before receiving the open pkt should defer
  dres = ch.DeliverPacket(packet().body("ping 2").b())
  assertDeferred(assert, err)

  // read that happens before receiving the open pkt should defer
  rres = ch.ReadPacket()
  assertDeferred(assert, rres)

  // in opening state
  assert.Equal(OpeningChannelState, ch.State())

  // receive open packet
  ch.ReceivePacket(packet().body("pong").c(1).seq(0).ack(0).b())

  // in opening state
  assert.Equal(OpeningChannelState, ch.State())

  // read that happens after receiving the open pkt should succeed
  rres = ch.ReadPacket()
  pkt, err = rres.wait()
  assert.NoError(err)
  assert.NotNil(pkt)
  assertC(assert, pkt, 1)
  assertNoType(assert, pkt)
  assertSeq(assert, pkt, 0)
  assertAck(assert, pkt, 0)
  assertBody(assert, pkt, "pong")

  // in open state
  assert.Equal(OpenChannelState, ch.State())
}

type promise interface {
  deferred() bool
}

func assertDeferred(assert *assert.Assertions, p promise) {
  assert.True(p.deferred(), "must be deferred")
}

func assertBody(assert *assert.Assertions, pkt *lob.Packet, expected string) {
  if pkt != nil {
    assert.Equal(expected, string(pkt.Body))
  }
}

func assertC(assert *assert.Assertions, pkt *lob.Packet, expected uint32) {
  if pkt != nil {
    actual, ok := pkt.Header().GetUint32("c")
    assert.True(ok, "c must be present")
    assert.Equal(expected, actual)
  }
}

func assertType(assert *assert.Assertions, pkt *lob.Packet, expected string) {
  if pkt != nil {
    actual, ok := pkt.Header().GetString("type")
    assert.True(ok, "type must be present")
    assert.Equal(expected, actual)
  }
}

func assertSeq(assert *assert.Assertions, pkt *lob.Packet, expected uint32) {
  if pkt != nil {
    actual, ok := pkt.Header().GetUint32("seq")
    assert.True(ok, "seq must be present")
    assert.Equal(expected, actual)
  }
}

func assertAck(assert *assert.Assertions, pkt *lob.Packet, expected uint32) {
  if pkt != nil {
    actual, ok := pkt.Header().GetUint32("ack")
    assert.True(ok, "ack must be present")
    assert.Equal(expected, actual)
  }
}

func assertNoType(assert *assert.Assertions, pkt *lob.Packet) {
  if pkt != nil {
    _, ok := pkt.Header().GetString("type")
    assert.False(ok, "type must be absent")
  }
}

func assertNoSeq(assert *assert.Assertions, pkt *lob.Packet) {
  if pkt != nil {
    _, ok := pkt.Header().GetUint32("seq")
    assert.False(ok, "seq must be absent")
  }
}

func assertNoAck(assert *assert.Assertions, pkt *lob.Packet) {
  if pkt != nil {
    _, ok := pkt.Header().GetUint32("ack")
    assert.False(ok, "ack must be absent")
  }
}

type packetBuilder struct {
  pkt *lob.Packet
}

func packet() packetBuilder {
  return packetBuilder{&lob.Packet{}}
}

func (p packetBuilder) body(s string) packetBuilder {
  p.pkt.Body = []byte(s)
  return p
}

func (p packetBuilder) header(k string, v interface{}) packetBuilder {
  p.pkt.Header().Set(k, v)
  return p
}

func (p packetBuilder) c(v uint32) packetBuilder {
  return p.header("c", v)
}

func (p packetBuilder) seq(v uint32) packetBuilder {
  return p.header("seq", v)
}

func (p packetBuilder) ack(v uint32) packetBuilder {
  return p.header("ack", v)
}

func (p packetBuilder) b() *lob.Packet {
  return p.pkt
}
