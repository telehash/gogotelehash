package bridge

import (
	"encoding/hex"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
)

func (mod *module) peerVia(router *e3x.Exchange, to hashname.H, body *bufpool.Buffer) error {
	ch, err := router.Open("peer", false)
	if err != nil {
		return err
	}
	defer ch.Kill()

	pkt := lob.New(body.RawBytes())
	pkt.Header().SetString("peer", string(to))
	ch.WritePacket(pkt)

	return nil
}

func (mod *module) introduceVia(router *e3x.Exchange, to hashname.H) error {
	localIdent, err := mod.e.LocalIdentity()
	if err != nil {
		return err
	}

	keys := localIdent.Keys()
	parts := hashname.PartsFromKeys(keys)

	for csid, key := range keys {
		inner := lob.New(key.Public())
		for partCSID, part := range parts {
			if partCSID == csid {
				inner.Header().SetBool(hex.EncodeToString([]byte{partCSID}), true)
			} else {
				inner.Header().SetString(hex.EncodeToString([]byte{partCSID}), part)
			}
		}

		body, err := lob.Encode(inner)
		if err != nil {
			return err
		}

		err = mod.peerVia(router, to, body)
		if err != nil {
			return err
		}
	}

	return nil
}

func (mod *module) handle_peer(ch *e3x.Channel) {
	defer ch.Kill()

	log := mod.log.From(ch.RemoteHashname()).To(mod.e.LocalHashname())

	// MUST allow router role
	if mod.config.DisableRouter {
		log.Println("drop: router disabled")
		return
	}

	pkt, err := ch.ReadPacket()
	if err != nil {
		log.Printf("drop: failed to read packet: %s", err)
		return
	}

	peerStr, ok := pkt.Header().GetString("peer")
	if !ok {
		log.Printf("drop: no peer in packet")
		return
	}
	peer := hashname.H(peerStr)

	// MUST have link to either endpoint
	if mod.e.GetExchange(ch.RemoteHashname()) == nil && mod.e.GetExchange(peer) == nil {
		log.Printf("drop: no link to either peer")
		return
	}

	// MUST pass firewall
	if mod.config.AllowPeer != nil && !mod.config.AllowPeer(ch.RemoteHashname(), peer) {
		log.Printf("drop: blocked by firewall")
		return
	}

	ex := mod.e.GetExchange(peer)
	if ex == nil {
		log.Printf("drop: no exchange to target")
		// resolve?
		return
	}

	token := cipherset.ExtractToken(pkt.Body(nil))
	if token != cipherset.ZeroToken {
		// add bridge back to requester
		mod.RouteToken(token, ch.Exchange())
	}

	mod.connect(ex, bufpool.New().Set(pkt.Body(nil)))
}
