package peers

import (
	"encoding/hex"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/modules/bridge"
)

func (mod *module) peerVia(router *e3x.Exchange, to hashname.H, body []byte) error {
	ch, err := router.Open("peer", false)
	if err != nil {
		return err
	}
	defer e3x.ForgetterFromEndpoint(mod.e).ForgetChannel(ch)

	pkt := &lob.Packet{}
	pkt.Body = body
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
		inner := &lob.Packet{}
		inner.Body = key.Public()
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
	defer e3x.ForgetterFromEndpoint(mod.e).ForgetChannel(ch)

	log := mainLog.From(ch.RemoteHashname()).To(mod.e.LocalHashname())

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
	if !(mod.m.HasLink(ch.RemoteHashname()) || mod.m.HasLink(peer)) {
		log.Printf("drop: no link to either peer")
		return
	}

	// MUST pass firewall
	if mod.config.AllowPeer != nil && !mod.config.AllowPeer(ch.RemoteHashname(), peer) {
		log.Printf("drop: blocked by firewall")
		return
	}

	ex := mod.m.Exchange(peer)
	if ex == nil {
		ex, _ = mod.e.Dial(e3x.HashnameIdentifier(peer))
	}
	if ex == nil {
		log.Printf("drop: no exchange to target")
		// resolve?
		return
	}

	token := cipherset.ExtractToken(pkt.Body)
	if token != cipherset.ZeroToken {
		// add bridge back to requester
		bridge.FromEndpoint(mod.e).RouteToken(token, ch.Exchange())
	}

	mod.connect(ex, pkt.Body)
}
