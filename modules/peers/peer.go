package peers

import (
	"encoding/hex"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/modules/bridge"
)

func (mod *module) introduceVia(router *e3x.Exchange, to hashname.H) error {
	localIdent, err := mod.e.LocalIdentity()
	if err != nil {
		return err
	}

	keys := localIdent.Keys()
	parts := hashname.PartsFromKeys(keys)
	forgetter := e3x.ForgetterFromEndpoint(mod.e)

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

		ch, err := router.Open("peer", false)
		if err != nil {
			return err
		}

		pkt := &lob.Packet{}
		pkt.Body = body
		pkt.Header().SetString("peer", string(to))
		ch.WritePacket(pkt)

		forgetter.ForgetChannel(ch)
	}

	return nil
}

func (mod *module) handle_peer(ch *e3x.Channel) {
	defer e3x.ForgetterFromEndpoint(mod.e).ForgetChannel(ch)

	// MUST allow router role
	if mod.config.DisableRouter {
		return
	}

	pkt, err := ch.ReadPacket()
	if err != nil {
		return
	}

	peerStr, ok := pkt.Header().GetString("peer")
	if !ok {
		return
	}
	peer := hashname.H(peerStr)

	// MUST have link to either endpoint
	if !mod.m.HasLink(ch.RemoteHashname()) && !mod.m.HasLink(peer) {
		return
	}

	// MUST pass firewall
	if mod.config.AllowPeer != nil && !mod.config.AllowPeer(ch.RemoteHashname(), peer) {
		return
	}

	ex := mod.m.Exchange(peer)
	if ex == nil {
		// resolve?
		return
	}

	token := cipherset.ExtractToken(pkt.Body)
	if token != cipherset.ZeroToken {
		// add bridge
		bridge.FromEndpoint(mod.e).RouteToken(token, ex)
	}

	mod.connect(ex, pkt.Body)
}
