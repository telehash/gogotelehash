package telehash

import (
	"encoding/hex"
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

	paths := NetPaths{}

	if h.sw.AllowRelay {
		relay := to.NetPaths().FirstOfType(&relay_net_path{})
		if relay == nil {
			c, err := make_rand(16)
			if err != nil {
				h.log.Debugf("error: %s", err)
				return
			}

			relay = to.AddNetPath(&relay_net_path{
				C: hex.EncodeToString(c),
			})
		}
		paths = append(paths, relay)
	}

	for _, via := range to.ViaTable() {
		h.log.Noticef("peering=%s via=%s", to_hn.Short(), via.Short())

		options := ChannelOptions{To: via, Type: "peer", Reliablility: UnreliableChannel}
		channel, err := h.sw.main.OpenChannel(options)
		if err != nil {
			continue
		}

		channel.snd_pkt(&pkt_t{
			hdr: pkt_hdr_t{
				Peer:  to_hn.String(),
				Paths: paths,
				End:   true,
			},
		})
	}
}

func (h *peer_handler) serve_peer(channel Channel) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	from_peer := h.sw.main.GetPeer(channel.To())

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

	to_peer := h.sw.main.GetPeer(peer_hashname)
	if to_peer == nil {
		return
	}

	pubkey, err := enc_DER_RSA(from_peer.PublicKey())
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	paths := pkt.hdr.Paths
	for _, np := range from_peer.NetPaths() {
		if np.IncludeInConnect() {
			paths = append(paths, np)
		}
	}
	h.log.Noticef("received peer-cmd: from=%s to=%s paths=%s", channel.To().Short(), peer_hashname.Short(), paths)

	options := ChannelOptions{To: peer_hashname, Type: "connect", Reliablility: UnreliableChannel}
	channel, err = h.sw.main.OpenChannel(options)
	if err != nil {
		h.log.Debugf("peer:connect err=%s", err)
	}

	err = channel.snd_pkt(&pkt_t{
		hdr: pkt_hdr_t{
			Paths: paths,
			End:   true,
		},
		body: pubkey,
	})
	if err != nil {
		h.log.Debugf("peer:connect err=%s", err)
	}
}

func (h *peer_handler) serve_connect(channel Channel) {
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

	peer, newpeer := h.sw.main.AddPeer(hashname)

	peer.SetPublicKey(pubkey)

	for _, np := range pkt.hdr.Paths {
		peer.AddNetPath(np)
	}

	if newpeer {
		peer.set_active_paths(peer.NetPaths())
	}

	h.log.Noticef("received connect-cmd: peer=%s", peer)

	line := h.sw.main.GetLine(peer.Hashname())
	line.EnsureRunning()

	for _, np := range peer.NetPaths() {
		h.log.Noticef("snd-open: to=%s netpath=%s", hashname.Short(), np)
		line.SndOpen(np)
	}
}
