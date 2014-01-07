package telehash

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fd/go-util/log"
	"hash/fnv"
	"sync/atomic"
	"time"
)

const _RELAY_DEADLINE = 12 * time.Second

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
}

func (h *relay_handler) PopulateStats(s *SwitchStats) {
	s.RelayNumSendPackets += atomic.LoadUint64(&h.num_pkt_snd)
	s.RelayNumSendPacketErrors += atomic.LoadUint64(&h.num_err_pkt_snd)
	s.RelayNumRelayedPackets += atomic.LoadUint64(&h.num_pkt_rly)
	s.RelayNumRelayedPacketErrors += atomic.LoadUint64(&h.num_err_pkt_rly)
	s.RelayNumReceivedPackets += atomic.LoadUint64(&h.num_pkt_rcv)
	s.RelayNumReceivedPacketErrors += atomic.LoadUint64(&h.num_err_pkt_rcv)
}

func (h *relay_handler) rcv(pkt *pkt_t) {
	var (
		err error
		// c     = pkt.hdr.C
		to    = pkt.hdr.To
		to_hn Hashname
	)

	to_hn, err = HashnameFromString(to)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rcv, 1)
		h.log.Noticef("error: %s opkt=%+v", err, pkt)
		return
	}

	if to_hn == pkt.peer.hashname {
		return // drop
	} else if to_hn == h.sw.hashname {
		h.rcv_self(pkt)
	} else {
		h.rcv_other(pkt, to_hn)
	}
}

func (h *relay_handler) rcv_self(opkt *pkt_t) {
	ipkt, err := parse_pkt(opkt.body, nil, &relay_net_path{opkt.hdr.C, ZeroHashname, 0, 0})
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

	atomic.AddUint64(&h.num_pkt_rcv, 1)
	h.log.Debugf("rcv-self: %+v %q", opkt.hdr, opkt.body)
	return
}

func (h *relay_handler) rcv_other(opkt *pkt_t, to Hashname) {
	line := h.sw.main.lines[to]
	if line == nil || line.State() != line_opened {
		return // drop
	}

	opkt = &pkt_t{hdr: pkt_hdr_t{Type: "relay", C: opkt.hdr.C, To: opkt.hdr.To}, body: opkt.body}
	cmd := cmd_snd_pkt{nil, line, opkt, nil}
	go h.sw.reactor.Call(&cmd)
	if cmd.err != nil {
		atomic.AddUint64(&h.num_err_pkt_rly, 1)
		h.log.Noticef("error: %s opkt=%+v", cmd.err, opkt)
		return
	}

	atomic.AddUint64(&h.num_pkt_rly, 1)
	h.log.Debugf("rcv-other: %+v %q", opkt.hdr, opkt.body)
}

func make_relay_net_path() NetPath {
	c, err := make_rand(16)
	if err != nil {
		return nil
	}

	return &relay_net_path{
		C: hex.EncodeToString(c),
	}
}

type relay_net_path struct {
	C              string
	via            Hashname
	hash           uint32
	priority_delta net_path_priority
}

func (n *relay_net_path) Priority() int {
	return 0 + n.priority_delta.Get()
}

func (n *relay_net_path) Demote() {
	n.priority_delta.Add(-1)
}

func (n *relay_net_path) Break() {
	n.priority_delta.Add(-3 - n.Priority())
}

func (n *relay_net_path) ResetPriority() {
	n.priority_delta.Reset()
}

func (n *relay_net_path) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "relay")
		fmt.Fprintln(h, n.C)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *relay_net_path) AddressForSeek() (ip string, port int, ok bool) {
	return "", 0, false
}

func (n *relay_net_path) IncludeInConnect() bool {
	return false
}

func (n *relay_net_path) SendNatBreaker() bool {
	return false
}

func (n *relay_net_path) String() string {
	return fmt.Sprintf("<relay c=%s via=%s>", n.C, n.via.Short())
}

func (n *relay_net_path) Send(sw *Switch, pkt *pkt_t) error {
	var (
		h      = &sw.relay_handler
		line   *line_t
		routed bool
	)

REROUTE:
	if n.via == ZeroHashname {
		routed = true
		for _, via := range pkt.peer.ViaTable() {
			line := sw.main.lines[via]
			if line == nil || line.State() == line_opened {
				continue
			}

			if _, is_relay := line.peer.ActivePath().(*relay_net_path); is_relay {
				continue
			}

			n.via = via
			break
		}
	}

	if n.via == ZeroHashname {
		return nil // drop
	}

	line = sw.main.lines[n.via]
	if line == nil || line.State() == line_opened {
		n.via = ZeroHashname
		if routed {
			return nil // drop
		}
		goto REROUTE
	}

	h.log.Noticef("routing %s via=%+v", n, pkt.peer.ViaTable())

	data, err := pkt.format_pkt()
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_snd, 1)
		h.log.Noticef("error: %s", err)
		return nil
	}

	opkt := &pkt_t{hdr: pkt_hdr_t{Type: "relay", C: n.C, To: pkt.peer.hashname.String()}, body: data}
	cmd := cmd_snd_pkt{nil, line, opkt, nil}
	go func() {
		h.sw.reactor.Call(&cmd)
		if cmd.err != nil {
			n.via = ZeroHashname
			atomic.AddUint64(&h.num_err_pkt_snd, 1)
			h.log.Noticef("error: %s opkt=%+v", cmd.err, opkt)
			return
		}

		atomic.AddUint64(&h.num_pkt_snd, 1)
		h.log.Debugf("snd-self: %+v %q", opkt.hdr, opkt.body)
	}()

	return nil
}

func (n *relay_net_path) MarshalJSON() ([]byte, error) {
	var (
		j = struct {
			C string `json:"c"`
		}{
			C: n.C,
		}
	)

	return json.Marshal(j)
}

func (n *relay_net_path) UnmarshalJSON(data []byte) error {
	var (
		j struct {
			C string `json:"c"`
		}
	)

	err := json.Unmarshal(data, &j)
	if err != nil {
		return err
	}

	if j.C == "" {
		return fmt.Errorf("Invalid relay netpath")
	}

	n.C = j.C
	return nil
}
