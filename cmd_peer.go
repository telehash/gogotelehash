package telehash

import (
	"github.com/fd/go-util/log"
)

type peer_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *peer_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "peer-handler")

	sw.mux.HandleFunc("peer", h.serve_peer)
	sw.mux.HandleFunc("connect", h.serve_connect)
}

func (h *peer_handler) SendPeer(to *Peer) {
	to_hn := to.Hashname()

	h.sw.net.send_nat_breaker(to)

	paths := net_paths{}

	if h.sw.AllowRelay {
		relay := to.net_paths().FirstOfType("relay")
		if relay == nil {
			c, err := make_hex_rand(16)
			if err != nil {
				h.log.Noticef("error: %s", err)
				return
			}

			relay = to.add_net_path(&net_path{Network: "relay", Address: &relay_addr{C: c}})
		}
		paths = append(paths, relay)
	}

	for _, via := range to.ViaTable() {
		h.log.Noticef("peering=%s via=%s", to_hn.Short(), via.Short())

		options := ChannelOptions{To: via, Type: "peer", Reliablility: UnreliableChannel}
		channel, err := h.sw.Open(options)
		if err != nil {
			continue
		}

		channel.send_packet(&pkt_t{
			hdr: pkt_hdr_t{
				Peer:  to_hn.String(),
				Paths: paths,
				End:   true,
			},
		})
	}
}

func (h *peer_handler) serve_peer(channel *Channel) {
	pkt, err := channel.receive_packet()
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	from_peer := h.sw.GetPeer(channel.To())

	peer_hashname, err := HashnameFromString(pkt.hdr.Peer)
	if err != nil {
		h.log.Debug(err)
		return
	}

	if peer_hashname == h.sw.hashname {
		return
	}

	if peer_hashname == channel.To() {
		return
	}

	if from_peer.PublicKey() == nil {
		return
	}

	to_peer := h.sw.GetPeer(peer_hashname)
	if to_peer == nil {
		return
	}

	pubkey, err := enc_DER_RSA(from_peer.PublicKey())
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	paths := pkt.hdr.Paths
	for _, np := range from_peer.net_paths() {
		if np.Address.PublishWithConnect() {
			paths = append(paths, np)
		}
	}
	h.log.Noticef("received peer-cmd: from=%s to=%s paths=%s", channel.To().Short(), peer_hashname.Short(), paths)

	options := ChannelOptions{To: peer_hashname, Type: "connect", Reliablility: UnreliableChannel}
	channel, err = h.sw.Open(options)
	if err != nil {
		h.log.Noticef("peer:connect err=%s", err)
	}

	err = channel.send_packet(&pkt_t{
		hdr: pkt_hdr_t{
			Paths: paths,
			End:   true,
		},
		body: pubkey,
	})
	if err != nil {
		h.log.Noticef("peer:connect err=%s", err)
	}
}

func (h *peer_handler) serve_connect(channel *Channel) {
	pkt, err := channel.receive_packet()
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	pubkey, err := dec_DER_RSA(pkt.body)
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	hashname, err := HashnameFromPublicKey(pubkey)
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	peer, newpeer := h.sw.AddPeer(hashname)

	peer.SetPublicKey(pubkey)
	peer.AddVia(channel.To())
	peer.is_down = false

	for _, np := range pkt.hdr.Paths {
		peer.add_net_path(np)
	}

	if newpeer {
		peer.set_active_paths(peer.net_paths())
	}

	h.log.Noticef("received connect-cmd: peer=%s paths=%s", peer, peer.active_path())

	h.sw.seek_handler.Seek(peer.Hashname(), h.sw.hashname)
}
