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

	h.sw.send_nat_breaker(to)

	var (
		paths     net_paths
		raw_paths raw_net_paths
	)

	if !h.sw.DenyRelay {
		relay := to.net_paths().FirstOfType("relay")
		if relay == nil {
			to.add_net_path(&net_path{Network: "relay", Address: make_relay_addr()})
		}
	}

	for _, n := range to.net_paths() {
		if n.Address.PublishWithPeer() {
			paths = append(paths, n)
		}
	}

	raw_paths, err := h.sw.encode_net_paths(paths)
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	for _, via := range to.ViaTable() {
		func() {
			h.log.Noticef("peering=%s via=%s", to_hn.Short(), via.Short())

			options := ChannelOptions{To: via, Type: "peer", Reliablility: UnreliableChannel}
			channel, err := h.sw.Open(options)
			if err != nil {
				return
			}
			defer channel.Close()

			channel.send_packet(&pkt_t{
				hdr: pkt_hdr_t{
					Peer:  to_hn.String(),
					Paths: raw_paths,
					End:   true,
				},
			})
		}()

	}
}

func (h *peer_handler) serve_peer(channel *Channel) {
	pkt, err := channel.receive_packet()
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	from_peer := h.sw.get_peer(channel.To())

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

	to_peer := h.sw.get_peer(peer_hashname)
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
			raw, err := h.sw.encode_net_path(np)
			if err == nil {
				paths = append(paths, raw)
			}
		}
	}
	h.log.Noticef("received peer-cmd: from=%s to=%s paths=%s", channel.To().Short(), peer_hashname.Short(), paths)

	options := ChannelOptions{To: peer_hashname, Type: "connect", Reliablility: UnreliableChannel}
	channel, err = h.sw.Open(options)
	if err != nil {
		h.log.Noticef("peer:connect err=%s", err)
	}
	defer channel.Close()

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

	peer, _ := h.sw.add_peer(hashname)

	peer.SetPublicKey(pubkey)
	peer.AddVia(channel.To())

	paths, err := h.sw.decode_net_paths(pkt.hdr.Paths)
	if err != nil {
		h.log.Noticef("error: %s", err)
		return
	}

	for _, np := range paths {
		if np.Network == "relay" {
			continue
		}
		peer.add_net_path(np)
	}

	if relay := paths.FirstOfType("relay"); relay != nil {
		for _, np := range peer.net_paths() {
			if np.Network == "relay" {
				peer.remove_net_path(np)
			}
		}
		peer.add_net_path(relay)
	}

	was_open := false
	if line := h.sw.get_line(hashname); line != nil {
		was_open = true
		line.SndOpen(nil)
	}

	h.log.Noticef("received connect-cmd: peer=%s was-open=%v path=%s paths=%s", peer, was_open, peer.active_path(), peer.net_paths())

	h.sw.path_handler.Negotiate(peer.hashname)
}
