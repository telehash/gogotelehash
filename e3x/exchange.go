package e3x

import (
	"encoding/binary"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/transports"
)

type exchangeState uint8

const (
	unknownExchangeState exchangeState = iota
	dialingExchangeState
	openedExchangeState
)

type exchange struct {
	state    exchangeState
	endpoint *Endpoint
	last_seq uint32
	next_seq uint32
	token    cipherset.Token
	hashname hashname.H
	csid     uint8
	cipher   cipherset.State
	qDial    []*opDial
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
		key := e.endpoint.key_for_cs(csid)
		if key == nil {
			return false
		}

		e.cipher, err = cipherset.NewState(csid, key, false)
		if err != nil {
			return false
		}

		e.csid = csid
	}

	if csid != e.csid {
		return false
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
		o.Body, err = e.cipher.EncryptHandshake(seq, hashname.PartsFromKeys(e.endpoint.keys))
		if err != nil {
			return false
		}

		err = e.endpoint.deliver(o, op.addr)
		if err != nil {
			return false
		}

		e.last_seq = seq
	}

	for _, op := range e.qDial {
		op.cErr <- nil
	}
	e.qDial = nil

	return true
}

func (e *exchange) deliver_handshake() error {
	var (
		seq = e.getNextSeq()
		o   = &lob.Packet{Head: []byte{e.csid}}
		err error
	)

	o.Body, err = e.cipher.EncryptHandshake(seq, hashname.PartsFromKeys(e.endpoint.keys))
	if err != nil {
		return err
	}

	err = e.endpoint.deliver(o, transports.All(e.hashname))
	if err != nil {
		return err
	}

	e.last_seq = seq
	return nil
}

func (e *exchange) getNextSeq() uint32 {
	seq := e.next_seq
	if seq < e.last_seq {
		seq = e.last_seq + 1
	}
	if seq == 0 {
		seq++
	}

	if e.cipher.IsHigh() {
		// must be odd
		if seq%2 == 0 {
			seq++
		}
	} else {
		// must be even
		if seq%2 == 1 {
			seq++
		}
	}

	e.next_seq = seq + 2
	return seq
}
