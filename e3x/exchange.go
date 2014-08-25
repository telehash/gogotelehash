package e3x

import (
	"encoding/binary"

	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
)

type Endpoint struct {
	keys         map[string]string
	inbound      <-chan *lob.Packet // transports -> endpoint
	outboundLow  chan<- *lob.Packet // endpoint -> transports
	outboundHigh <-chan *lob.Packet // channels -> endpoint (-> transports)
	tokens       map[cipherset.Token]*exchange
	hashnames    map[hashname.H]*exchange
}

type exchange struct {
	endpoint *Endpoint
	last_seq uint32
	token    cipherset.Token
	hashname hashname.H
	cipher   cipherset.State
}

func (e *Endpoint) Run() error {
	for {
		select {

		case pkt := <-e.inbound:
			// handle inbound packet
			e.handle_inbound(pkt)

		case pkt := <-e.outboundHigh:
			// hanndle outbound packet
			e.handle_outbound(pkt)

		}
	}
}

func (e *Endpoint) handle_inbound(pkt *lob.Packet) {
	// if len(HEAD) == 1
	// then handle_inbound_handshake
	// else handle_inbound_packet
}

func (e *Endpoint) handle_inbound_handshake(pkt *lob.Packet) {
	var (
		token cipherset.Token
	)

	if len(pkt.Body) < 4+16 {
		return // DROP
	}

	// extract TOKEN
	copy(token[:], pkt.Body[4:4+16])

	// find / create exchange
	ex, found := e.tokens[token]
	if !found {
		ex = &exchange{endpoint: e, token: token}
	}

	valid := ex.handle_inbound_handshake(pkt)

	if valid && !found {
		e.tokens[token] = ex
		e.hashnames[ex.hashname] = ex
	}
}

func (e *exchange) handle_inbound_handshake(pkt *lob.Packet) bool {
	var (
		seq = binary.BigEndian.Uint32(pkt.Body[:4])
		err error
	)

	if seq < e.last_seq {
		return false
	}

	if e.cipher == nil {
		e.cipher = cipherset.NewState(pkt.Head[0], e.endpoint.keys, false)
	}

	_, key, compact, err := e.cipher.DecryptHandshake(pkt.Body)
	if err != nil {
		return false
	}

	hn, err := hashname.FromKeyAndIntermediates(id, key, compact)
	if err != nil {
		return false
	}

	if seq > e.last_seq {
		o := &lob.Packet{Head: []byte{pkt.Head[0]}}
		o.Body, err = e.cipher.EncryptHandshake(seq, e.endpoint.keys)
		if err != nil {
			return false
		}

		err = e.endpoint.deliver(o)
		if err != nil {
			return false
		}

		e.last_seq = seq
	}
}

func (e *Endpoint) handle_outbound(pkt *lob.Packet) {

}

func (e *Endpoint) deliver(pkt *Packet) error {
	e.outboundLow <- pkt
	return nil
}
