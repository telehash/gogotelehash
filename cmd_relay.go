package telehash

import (
	"fmt"
	"github.com/fd/go-util/log"
	"hash/fnv"
	"sync/atomic"
	"time"
)

const _RELAY_DEADLINE = 10 * time.Second

type relay_handler struct {
	sw  *Switch
	log log.Logger

	num_pkt_snd     uint64
	num_err_pkt_snd uint64
	num_pkt_rly     uint64
	num_err_pkt_rly uint64
	num_pkt_rcv     uint64
	num_err_pkt_rcv uint64
}

func (h *relay_handler) init(sw *Switch) {
	h.sw = sw
	h.log = sw.log.Sub(log.DEFAULT, "relay_handler")

	sw.mux.handle_func("relay", h.serve)
}

func (h *relay_handler) PopulateStats(s *SwitchStats) {
	s.RelayNumSendPackets += atomic.LoadUint64(&h.num_pkt_snd)
	s.RelayNumSendPacketErrors += atomic.LoadUint64(&h.num_err_pkt_snd)
	s.RelayNumRelayedPackets += atomic.LoadUint64(&h.num_pkt_rly)
	s.RelayNumRelayedPacketErrors += atomic.LoadUint64(&h.num_err_pkt_rly)
	s.RelayNumReceivedPackets += atomic.LoadUint64(&h.num_pkt_rcv)
	s.RelayNumReceivedPacketErrors += atomic.LoadUint64(&h.num_err_pkt_rcv)
}

func (h *relay_handler) serve(channel *channel_t) {
	pkt, err := channel.pop_rcv_pkt()
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rcv, 1)
		h.log.Noticef("error: %s", err)
		return
	}
	h.log.Debugf("rcv: %+v %q", pkt.hdr, pkt.body)

	to, err := HashnameFromString(pkt.hdr.To)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rcv, 1)
		h.log.Noticef("error: %s", err)
		return
	}

	if to == h.sw.LocalHashname() {
		h.serve_self(channel, pkt)
	} else {
		h.serve_other(channel, pkt, to)
	}
}

// Handle relay channels targeted at the local switch.
func (h *relay_handler) serve_self(channel *channel_t, opkt *pkt_t) {
	netpath := &relay_net_path{ZeroHashname, ZeroHashname, channel, 0, 0}

	h.self_rcv_pkt(opkt, netpath)

	for {
		opkt, err := channel.pop_rcv_pkt()
		if err != nil {
			atomic.AddUint64(&h.num_err_pkt_rcv, 1)
			h.log.Noticef("error: %s opkt=%+v", err, opkt)
			return
		}

		h.self_rcv_pkt(opkt, netpath)
	}
}

func (h *relay_handler) self_rcv_pkt(opkt *pkt_t, netpath NetPath) {
	if len(opkt.body) < 4 {
		return
	}

	ipkt, err := parse_pkt(opkt.body, nil, netpath)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rcv, 1)
		h.log.Noticef("error: %s opkt=%+v", err, opkt)
		return
	}

	err = h.sw.main.RcvPkt(ipkt)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rcv, 1)
		h.log.Noticef("error: %s ipkt=%+v", err, ipkt)
		return
	}

	h.log.Debugf("rcv-self: %+v %q", ipkt.hdr)

	atomic.AddUint64(&h.num_pkt_rcv, 1)
}

func (h *relay_handler) serve_other(a *channel_t, opkt *pkt_t, to Hashname) {
	opkt = &pkt_t{hdr: pkt_hdr_t{Type: "relay", To: opkt.hdr.To}, body: opkt.body}
	b, err := h.sw.main.OpenChannel(to, opkt, true)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_snd, 1)
		h.log.Noticef("error: %s", err)
		return
	}

	break_ch := make(chan bool, 3)
	deadline := time.NewTimer(_RELAY_DEADLINE)

	go h.copy(a, b, break_ch, deadline)
	go h.copy(b, a, break_ch, deadline)

	defer b.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true}})

	select {
	case <-deadline.C:
		break_ch <- true
	case <-break_ch:
		break_ch <- true
	}
}

func (h *relay_handler) copy(dst, src *channel_t, break_chan chan bool, deadline *time.Timer) {
	var (
		tick      = time.Now()
		pkt_count = 0
	)

	for {
		src.set_rcv_deadline(tick.Add(time.Second))

		select {
		case <-break_chan:
			break_chan <- true
			return
		default:
		}

		opkt, err := src.pop_rcv_pkt()
		if err == ErrTimeout {
			continue
		}
		if err != nil {
			atomic.AddUint64(&h.num_err_pkt_rcv, 1)
			h.log.Noticef("error: %s", err)
			break_chan <- true
			return
		}
		h.log.Debugf("rcv-cp: %+v %q", opkt.hdr, opkt.body)

		if time.Now().Sub(tick) > time.Second {
			tick = time.Now()
			pkt_count = 0
		}
		pkt_count++
		if pkt_count > 5 {
			atomic.AddUint64(&h.num_err_pkt_rly, 1)
			continue // drop
		}

		opkt = &pkt_t{hdr: pkt_hdr_t{Type: "relay", To: opkt.hdr.To}, body: opkt.body}
		err = dst.snd_pkt(opkt)
		if err != nil {
			atomic.AddUint64(&h.num_err_pkt_rly, 1)
			h.log.Noticef("error: %s", err)
			break_chan <- true
			return
		}

		deadline.Reset(_RELAY_DEADLINE)
		atomic.AddUint64(&h.num_pkt_rly, 1)
	}
}

type relay_net_path struct {
	to             Hashname
	via            Hashname
	channel        *channel_t
	hash           uint32
	priority_delta net_path_priority
}

func (n *relay_net_path) Priority() int {
	return 0 + n.priority_delta.Get()
}

func (n *relay_net_path) SendOpen() {
	n.priority_delta.Add(-1)
}

func (n *relay_net_path) ResetPriority() {
	n.priority_delta.Reset()
}

func (n *relay_net_path) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "relay")
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

func (n *relay_net_path) SendNatBreaker() bool {
	return false
}

func (n *relay_net_path) String() string {
	return "<net-relay>"
}

func (n *relay_net_path) Send(sw *Switch, pkt *pkt_t) error {
	data, err := pkt.format_pkt()
	if err != nil {
		atomic.AddUint64(&sw.relay_handler.num_err_pkt_snd, 1)
		sw.relay_handler.log.Noticef("error: %s", err)
		return err
	}

	pkt = &pkt_t{hdr: pkt_hdr_t{Type: "relay", To: n.to.String()}, body: data}

	if n.channel == nil {
		c, err := sw.main.OpenChannel(n.via, pkt, true)
		if err != nil {
			atomic.AddUint64(&sw.relay_handler.num_err_pkt_snd, 1)
			sw.relay_handler.log.Noticef("error: %s", err)
			n.channel = nil
			return err
		}

		n.channel = c
		atomic.AddUint64(&sw.relay_handler.num_pkt_snd, 1)

	} else {
		err = n.channel.snd_pkt(pkt)
		if err != nil {
			atomic.AddUint64(&sw.relay_handler.num_err_pkt_snd, 1)
			sw.relay_handler.log.Noticef("error: %s", err)
			n.channel = nil
			return err
		}

		atomic.AddUint64(&sw.relay_handler.num_pkt_snd, 1)
	}

	return nil
}
