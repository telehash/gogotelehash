package e3x

import (
  "encoding/binary"

  "bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
  "bitbucket.org/simonmenke/go-telehash/hashname"
  "bitbucket.org/simonmenke/go-telehash/lob"
)

type exchange struct {
  endpoint *Endpoint
  last_seq uint32
  token    cipherset.Token
  hashname hashname.H
  cipher   cipherset.State
}

func (e *exchange) received_handshake(op opReceived) bool {
  var (
    csid = op.pkt.Head[0]
    seq  = binary.BigEndian.Uint32(op.pkt.Body[:4])
    err  error
  )

  if seq < e.last_seq {
    return false
  }

  if e.cipher == nil {
    keyData := e.endpoint.key_for_cs(csid)
    if keyData == "" {
      return false
    }

    key, err := cipherset.DecodeKey(csid, keyData)
    if err != nil {
      return false
    }

    e.cipher, err = cipherset.NewState(csid, key, false)
    if err != nil {
      return false
    }
  }

  _, key, compact, err := e.cipher.DecryptHandshake(op.pkt.Body)
  if err != nil {
    return false
  }

  hn, err := hashname.FromKeyAndIntermediates(csid, key.Bytes(), compact)
  if err != nil {
    return false
  }

  if e.hashname == "" {
    e.hashname = hn
  }

  if e.hashname != hn {
    return false
  }

  if seq > e.last_seq {
    o := &lob.Packet{Head: []byte{csid}}
    o.Body, err = e.cipher.EncryptHandshake(seq, e.endpoint.keys)
    if err != nil {
      return false
    }

    err = e.endpoint.deliver(o, op.addr)
    if err != nil {
      return false
    }

    e.last_seq = seq
  }

  return true
}
