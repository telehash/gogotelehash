package e3x

import (
  "sync"

  "bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
  "bitbucket.org/simonmenke/go-telehash/hashname"
  "bitbucket.org/simonmenke/go-telehash/lob"
  "bitbucket.org/simonmenke/go-telehash/transports"
)

type Endpoint struct {
  wg         sync.WaitGroup
  keys       map[uint8]string
  transports transports.Manager

  cReceived chan opReceived
  // outboundHigh <-chan *lob.Packet // channels -> endpoint (-> transports)
  tokens    map[cipherset.Token]*exchange
  hashnames map[hashname.H]*exchange
}

type opReceived struct {
  pkt  *lob.Packet
  data []byte
  addr transports.ResolvedAddr
}

func (e *Endpoint) run_receiver() {
  defer e.wg.Done()

  for {
    pkt, addr, err := e.transports.Receive()
    if err == transports.ErrManagerTerminated {
      break
    }
    if err != nil {
      continue // report error
    }

    e.cReceived <- opReceived{nil, pkt, addr}
  }
}

func (e *Endpoint) run() {
  defer e.wg.Done()

  for {
    select {

    case op := <-e.cReceived:
      // handle inbound packet
      e.received(op)

      // case pkt := <-e.outboundHigh:
      //   // hanndle outbound packet
      //   e.handle_outbound(pkt)

    }
  }
}

func (e *Endpoint) received(op opReceived) {
  pkt, err := lob.Decode(op.data)
  if err != nil {
    // drop
    return
  }

  op.pkt = pkt

  if len(pkt.Head) == 1 {
    e.received_handshake(op)
    return
  }

  if len(pkt.Head) == 0 {
    e.received_packet(pkt, op.addr)
    return
  }

  // drop
}

func (e *Endpoint) received_handshake(op opReceived) {
  var (
    token cipherset.Token
  )

  if len(op.pkt.Body) < 4+16 {
    return // DROP
  }

  // extract TOKEN
  copy(token[:], op.pkt.Body[4:4+16])

  // find / create exchange
  ex, found := e.tokens[token]
  if !found {
    ex = &exchange{endpoint: e, token: token}
  }

  valid := ex.received_handshake(op)

  if valid && !found {
    e.tokens[token] = ex
    e.hashnames[ex.hashname] = ex
  }

  if valid {
    e.transports.Associate(ex.hashname, op.addr)
  }
}

func (e *Endpoint) received_packet(pkt *lob.Packet, addr transports.ResolvedAddr) {

}

func (e *Endpoint) handle_outbound(pkt *lob.Packet) {

}

func (e *Endpoint) deliver(pkt *lob.Packet, addr transports.Addr) error {
  data, err := lob.Encode(pkt)
  if err != nil {
    return err
  }

  return e.transports.Deliver(data, addr)
}

func (e *Endpoint) key_for_cs(csid uint8) string {
  return e.keys[csid]
}
