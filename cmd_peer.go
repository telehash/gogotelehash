package telehash

import (
	"github.com/fd/go-util/log"
	"net"
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

func (h *peer_handler) SendPeer(to *Peer) {
	to_hn := to.Hashname()

	for via, addr := range to.ViaTable() {
		h.log.Noticef("peering=%s via=%s", to_hn.Short(), via.Short())

		h.sw.net.send_nat_breaker(addr)

		h.sw.main.OpenChannel(via, &pkt_t{
			hdr: pkt_hdr_t{
				Type: "peer",
				Peer: to_hn.String(),
				End:  true,
			},
		}, true)
	}
}

func (h *peer_handler) serve_peer(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	from_peer := channel.line.peer

	peer_hashname, err := HashnameFromString(pkt.hdr.Peer)
	if err != nil {
		h.log.Debug(err)
		return
	}

	if peer_hashname == h.sw.hashname {
		return
	}

	if peer_hashname == from_peer.Hashname() {
		return
	}

	if from_peer.PublicKey() == nil {
		return
	}

	to_peer := h.sw.main.GetPeer(peer_hashname)
	if to_peer == nil {
		return
	}

	pubkey, err := enc_DER_RSA(from_peer.PublicKey())
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	h.log.Noticef("received peer-cmd: from=%s to=%s", from_peer.Hashname().Short(), peer_hashname.Short())

	_, err = h.sw.main.OpenChannel(peer_hashname, &pkt_t{
		hdr: pkt_hdr_t{
			Type: "connect",
			IP:   ip,
			Port: port,
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

	hashname, err := HashnameFromPublicKey(pubkey)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	ip := net.ParseIP(pkt.hdr.IP)
	if err != nil {
		h.log.Debugf("error: %s", "invalid IP address")
		return
	}

	peer, disc := h.sw.main.AddPeer(hashname)

	peer.AddNetPath(NetPath{
		Flags:   net.FlagMulticast | net.FlagBroadcast,
		Address: &net.IPAddr{IP: ip},
		Port:    pkt.hdr.Port,
		MTU:     1500,
	})

	h.log.Noticef("received connect-cmd: peer=%s local=%+v", addr, pkt.hdr.Local)

	reply := make(chan *line_t)
	h.sw.main.get_line_chan <- cmd_line_get{peer.Hashname(), NetPath{}, nil, reply}
	line := <-reply
}
