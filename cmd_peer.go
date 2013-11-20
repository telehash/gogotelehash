package telehash

import (
	"fmt"
	"github.com/fd/go-util/log"
	"net"
	"strconv"
)

type peer_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *peer_handler) init_peer_handler(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "peer-handler")

	sw.mux.handle_func("peer", h.serve_peer)
	sw.mux.handle_func("connect", h.serve_connect)
}

func (h *peer_handler) SendPeer(to *peer_t) error {
	h.log.Noticef("peering=%s via=%s", to.addr.hashname.Short(), to.addr.via.Short())

	if to.addr.via.IsZero() {
		return fmt.Errorf("peer has unknown via: %s", to)
	}

	if to.addr.addr != nil {
		// Deploy the nat breaker
		h.sw.net.send_nat_breaker(to.addr.addr)
	}

	_, err := h.sw.main.OpenChannel(to.addr.via, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "peer",
			Peer: to.addr.hashname.String(),
			End:  true,
		},
	}, true)

	if err != nil {
		h.log.Debugf("peer cmd err=%s", err)
	}

	return err
}

func (h *peer_handler) serve_peer(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	sender_addr := pkt.addr
	peer_hashname, err := HashnameFromString(pkt.hdr.Peer)
	if err != nil {
		h.log.Debug(err)
		return
	}

	if peer_hashname == h.sw.hashname {
		return
	}

	if peer_hashname == sender_addr.hashname {
		return
	}

	if sender_addr.pubkey == nil {
		return
	}

	pubkey, err := enc_DER_RSA(sender_addr.pubkey)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	h.log.Noticef("received peer-cmd: from=%s to=%s", sender_addr.hashname.Short(), peer_hashname.Short())

	_, err = h.sw.main.OpenChannel(peer_hashname, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "connect",
			IP:   sender_addr.addr.IP.String(),
			Port: sender_addr.addr.Port,
			End:  true,
		},
		body: pubkey,
	}, true)
	if err != nil {
		h.log.Debugf("peer:connect err=%s", err)
	}
}

func (h *peer_handler) serve_connect(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	pubkey, err := dec_DER_RSA(pkt.body)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	addr, err := make_addr(
		ZeroHashname,
		ZeroHashname,
		net.JoinHostPort(pkt.hdr.IP, strconv.Itoa(pkt.hdr.Port)),
		pubkey,
	)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	peer, _ := h.sw.main.AddPeer(addr)
	h.log.Noticef("received connect-cmd: peer=%s", addr)
	h.sw.seek_handler.Seek(peer.addr.hashname, h.sw.hashname)
}
