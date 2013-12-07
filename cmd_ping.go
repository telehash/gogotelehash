package telehash

import (
	"github.com/fd/go-util/log"
	"time"
)

type ping_handler struct {
	sw  *Switch
	log log.Logger
}

func (h *ping_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "ping-handler")

	sw.mux.handle_func("ping", h.serve_ping)
}

func (h *ping_handler) Ping(to Hashname) bool {
	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			Type: "ping",
		},
	}

	channel, err := h.sw.main.OpenChannel(to, pkt, true)
	if err != nil {
		h.log.Noticef("failed open: to=%s err=%s", to.Short(), err)
		return false
	}

	channel.set_rcv_deadline(time.Now().Add(10 * time.Second))

	_, err = channel.pop_rcv_pkt()
	if err != nil {
		h.log.Noticef("failed rcv: peer=%s err=%s", channel.line.peer, err)
		return false
	}

	h.log.Debugf("ping: peer=%s", channel.line.peer)
	return true
}

func (h *ping_handler) serve_ping(channel *channel_t) {
	_, err := channel.pop_rcv_pkt()
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.line.peer, err)
	}

	err = channel.snd_pkt(&pkt_t{
		hdr: pkt_hdr_t{
			End: true,
		},
	})
	if err != nil {
		h.log.Debugf("failed snd: peer=%s err=%s", channel.line.peer, err)
	}

	h.log.Debugf("pong: peer=%s", channel.line.peer)
}
