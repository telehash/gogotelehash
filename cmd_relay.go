package telehash

import (
	"github.com/fd/go-util/log"
	"hash/fnv"
	"time"
)

type relay_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *relay_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "relay-handler")

	sw.mux.handle_func("relay", h.serve)
}

func (h *relay_handler) serve(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("error: %s", err)
	}

	to, err := HashnameFromString(pkt.hdr.To)
	if err != nil {
		h.log.Debugf("error: %s", err)
	}

	if to == h.sw.LocalHashname() {
		h.serve_self(channel, pkt)
	} else {
		h.serve_other(channel, pkt, to)
	}
}

// Handle relay channels targeted at the local switch.
func (h *relay_handler) serve_self(channel *channel_t, opkt *pkt_t) {
	netpath := relay_net_path{channel, 0}

	ipkt, err := parse_pkt(opkt.body, nil, netpath)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	err = h.sw.main.RcvPkt(ipkt)
	if err != nil {
		h.log.Debugf("error: %s", err)
		return
	}

	for {
		opkt, err := channel.pop_rcv_pkt()
		if err != nil {
			h.log.Debugf("error: %s", err)
			return
		}

		ipkt, err := parse_pkt(opkt.body, nil, netpath)
		if err != nil {
			h.log.Debugf("error: %s", err)
			return
		}

		err = h.sw.main.RcvPkt(ipkt)
		if err != nil {
			h.log.Debugf("error: %s", err)
			return
		}
	}
}

type relay_net_path struct {
	channel *channel_t
	hash    uint32
}

func (n *relay_net_path) Priority() int {
	return 0
}

func (n *relay_net_path) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "relay")
		fmt.Fprintln(h, n.channel.channel_id)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *relay_net_path) AddressForSeek() (ip string, port int, ok bool) {
	return "", 0, false
}

func (n *relay_net_path) AddressForPeer() (ip string, port int, ok bool) {
	return "", 0, false
}

func (n *relay_net_path) packet_sender() packet_sender {
	panic("WIP")
}
