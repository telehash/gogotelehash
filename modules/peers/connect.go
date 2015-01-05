package peers

import (
	"encoding/hex"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/util/logs"
)

var mainLog = logs.Module("peers")

func (mod *module) connect(ex *e3x.Exchange, inner []byte) error {
	ch, err := ex.Open("connect", false)
	if err != nil {
		return err
	}

	defer e3x.ForgetterFromEndpoint(mod.e).ForgetChannel(ch)

	pkt := &lob.Packet{Body: inner}
	err = ch.WritePacket(pkt)
	if err != nil {
		return err
	}

	return nil
}

func (mod *module) handle_connect(ch *e3x.Channel) {
	defer e3x.ForgetterFromEndpoint(mod.e).ForgetChannel(ch)

	var (
		from        hashname.H
		localIdent  *e3x.Identity
		remoteIdent *e3x.Identity
		handshake   cipherset.Handshake
		err         error
	)

	localIdent, err = mod.e.LocalIdentity()
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
			key  = localIdent.Keys()[csid]
		)
		if key == nil {
			return
		}

		handshake, err = cipherset.DecryptHandshake(csid, key, inner.Body)
		if err != nil {
			return
		}

		from, err = hashname.FromIntermediates(handshake.Parts())
		if err != nil {
			return
		}

		remoteIdent, err = e3x.NewIdentity(cipherset.Keys{
			handshake.CSID(): handshake.PublicKey(),
		}, handshake.Parts(), nil)
		if err != nil {
			return
		}

	} else {
		// key packet

		var parts = make(cipherset.Parts)
		var csid uint8
		for key, value := range inner.Header().Extra {
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

		pubKey, err := cipherset.DecodeKeyBytes(csid, inner.Body, nil)
		if err != nil {
			return
		}

		remoteIdent, err = e3x.NewIdentity(cipherset.Keys{csid: pubKey}, parts, nil)
		if err != nil {
			return
		}
	}

	if from == "" {
		return
	}

	if mod.config.AllowConnect != nil && !mod.config.AllowConnect(from, ch.RemoteHashname()) {
		return
	}

	x, err := mod.e.GetExchange(remoteIdent)
	if err != nil {
		return
	}

	// when the BODY contains a handshake
	if handshake != nil {
		routerAddr := &peerAddr{
			router: ch.Exchange().RemoteHashname(),
		}

		resp, ok := x.ApplyHandshake(handshake, routerAddr)
		if !ok {
			return
		}

		if resp != nil {
			err = mod.peerVia(ch.Exchange(), from, resp)
			if err != nil {
				return
			}
		}
	}

	// when the BODY contains a key packet
	if handshake == nil {
		pkt, err := x.GenerateHandshake()
		if err != nil {
			return
		}

		err = mod.peerVia(ch.Exchange(), from, pkt)
		if err != nil {
			return
		}

		x.AddPathCandidate(&peerAddr{
			router: ch.Exchange().RemoteHashname(),
		})
	}

	// Notify on-exchange callbacks
	mod.getIntroduction(from).resolve(x, nil)
}
