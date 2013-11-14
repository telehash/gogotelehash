package telehash

import (
	"fmt"
	"net"
	"strconv"
)

func (to *peer_t) send_peer_cmd() error {
	if to.addr.via.IsZero() {
		return fmt.Errorf("peer has unknown via: %s", to)
	}

	via := to.sw.peers.get_peer(to.addr.via)
	if via == nil {
		return fmt.Errorf("peer has unknown via: %s", to)
	}

	if to.addr.addr != nil {
		// Deploy the nat breaker
		to.sw.net.send_nat_breaker(to.addr.addr)
	}

	_, err := via.open_channel(&pkt_t{
		hdr: pkt_hdr_t{
			Type: "peer",
			Peer: to.addr.hashname.String(),
			End:  true,
		},
	})

	if err != nil {
		Log.Debugf("peer cmd err=%s", err)
	}

	return err
}

func (h *peer_controller) serve_peer(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	peer_hashname, err := HashnameFromString(pkt.hdr.Peer)
	if err != nil {
		Log.Debug(err)
		return
	}

	if peer_hashname == h.get_local_hashname() {
		return
	}

	peer := h.get_peer(peer_hashname)
	if peer == nil {
		return
	}

	sender_addr := pkt.addr

	if peer_hashname == sender_addr.hashname {
		return
	}

	pubkey, err := enc_DER_RSA(sender_addr.pubkey)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	_, err = peer.open_channel(&pkt_t{
		hdr: pkt_hdr_t{
			Type: "connect",
			IP:   sender_addr.addr.IP.String(),
			Port: sender_addr.addr.Port,
			End:  true,
		},
		body: pubkey,
	})

	if err != nil {
		Log.Debugf("peer:connect err=%s", err)
	}
}

func (h *peer_controller) serve_connect(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	pubkey, err := dec_DER_RSA(pkt.body)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	addr, err := make_addr(
		ZeroHashname,
		ZeroHashname,
		net.JoinHostPort(pkt.hdr.IP, strconv.Itoa(pkt.hdr.Port)),
		pubkey,
	)
	if err != nil {
		Log.Debugf("error: %s", err)
		return
	}

	peer, _ := h.add_peer(addr)

	h.log.Debugf("(l=%s) addr=%s",
		h.get_local_hashname().Short(), addr)

	peer.send_seek_cmd(h.get_local_hashname())
}
