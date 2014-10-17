package peers

import (
	"encoding/hex"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/e3x/cipherset"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/modules/bridge"
)

func (p *peers) peerWithHashname(via *e3x.Addr, to hashname.H) error {
	localAddr, err := p.e.LocalAddr()
	if err != nil {
		return err
	}

	keys := localAddr.Keys()
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

		ch, err := p.e.Open(via, "peer", false)
		if err != nil {
			return err
		}

		pkt := &lob.Packet{}
		pkt.Body = body
		pkt.Header().SetString("peer", string(to))
		ch.WritePacket(pkt)

		e3x.ForgetterFromEndpoint(p.e).ForgetChannel(ch)
	}

	return nil
}

func (p *peers) handle_peer(ch *e3x.Channel) {
	defer e3x.ForgetterFromEndpoint(p.e).ForgetChannel(ch)

	// MUST allow router role
	if p.config.DisableRouter {
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
	if !p.m.HasLink(ch.RemoteHashname()) && !p.m.HasLink(peer) {
		return
	}

	// MUST pass firewall
	if p.config.AllowPeer != nil && !p.config.AllowPeer(ch.RemoteHashname(), peer) {
		return
	}

	ex := p.m.Exchange(peer)
	if ex == nil {
		// resolve?
		return
	}

	token := cipherset.ExtractToken(pkt.Body)
	if token != cipherset.ZeroToken {
		// add bridge
		bridge.FromEndpoint(p.e).RouteToken(token, ex)
	}

	p.connect(ex, pkt.Body)
}
