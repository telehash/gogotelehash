package telehash

import (
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

func (h *peer_handler) SendPeer(to *Peer) {
	to_hn := to.Hashname()

	h.sw.net.send_nat_breaker(to)

	for _, via := range to.ViaTable() {
		h.log.Noticef("peering=%s via=%s", to_hn.Short(), via.Short())

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

	for _, np := range from_peer.NetPaths() {
		if ip, port, ok := np.AddressForPeer(); ok {
			_, err = h.sw.main.OpenChannel(peer_hashname, &pkt_t{
				hdr: pkt_hdr_t{
					Type:  "connect",
					IP:    ip,
					Port:  port,
					Relay: pkt.hdr.Relay,
					End:   true,
				},
				body: pubkey,
			}, true)
			if err != nil {
				h.log.Debugf("peer:connect err=%s", err)
			}
		}
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

	netpath, err := ParseIPNetPath(net.JoinHostPort(pkt.hdr.IP, strconv.Itoa(pkt.hdr.Port)))
	if err != nil {
		h.log.Debugf("error: %s", "invalid address")
		return
	}

	peer, _ := h.sw.main.AddPeer(hashname)

	peer.SetPublicKey(pubkey)
	peer.AddNetPath(netpath)

	h.log.Noticef("received connect-cmd: peer=%s", peer)

	line := h.sw.main.GetLine(peer.Hashname())
	line.EnsureRunning()
	line.SndOpen(netpath)
}
