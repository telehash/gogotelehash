package peers

import (
	"encoding/hex"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
)

func (p *peers) connect(ex *e3x.Exchange, inner []byte) error {
	ch, err := ex.Open("connect", false)
	if err != nil {
		return err
	}

	defer e3x.ForgetterFromEndpoint(p.e).ForgetChannel(ch)

	pkt := &lob.Packet{Body: inner}
	err = ch.WritePacket(pkt)
	if err != nil {
		return err
	}

	return nil
}

func (p *peers) handle_connect(ch *e3x.Channel) {
	defer e3x.ForgetterFromEndpoint(p.e).ForgetChannel(ch)

	var (
		from      hashname.H
		localAddr *e3x.Addr
		err       error
	)

	localAddr, err = p.e.LocalAddr()
	if err != nil {
		return
	}

	pkt, err := ch.ReadPacket()
	if err != nil {
		return
	}

	inner, err := lob.Decode(pkt.Body)
	if err != nil {
		return
	}

	if len(inner.Head) == 1 {
		// handshake
		var (
			csid = inner.Head[0]
			key  = localAddr.Keys()[csid]
		)
		if key == nil {
			return
		}

		handshake, err := cipherset.DecryptHandshake(csid, key, inner.Body)
		if err != nil {
			return
		}

		from, err = hashname.FromIntermediates(handshake.Parts())
		if err != nil {
			return
		}

	} else {
		// key packet

		var parts = make(cipherset.Parts)
		var csid uint8
		for key, value := range inner.Header() {
			if len(key) != 2 {
				continue
			}

			keyData, err := hex.DecodeString(key)
			if err != nil {
				continue
			}

			partCSID := keyData[0]
			switch v := value.(type) {
			case bool:
				csid = partCSID
			case string:
				parts[partCSID] = v
			}
		}

		hn, err := hashname.FromKeyAndIntermediates(csid, inner.Body, parts)
		if err != nil {
			return
		}

		from = hn
	}

	if from == "" {
		return
	}

	if p.config.AllowConnect != nil && !p.config.AllowConnect(from, ch.RemoteHashname()) {
		return
	}

	panic("tap the packet into the endpoint")
}
