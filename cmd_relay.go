package telehash

import (
	"encoding/json"
	"fmt"
	"github.com/fd/go-util/log"
	"github.com/telehash/gogotelehash/net"
	"sync/atomic"
)

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
		err   error
		to    = pkt.priv_hdr.To
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
	go func() {
		ipkt, err := decode_packet(opkt.body)
		if err != nil {
			atomic.AddUint64(&h.num_err_pkt_rcv, 1)
			h.log.Noticef("error: %s opkt=%+v", err, opkt)
			return
		}

		ipkt.netpath = &net_path{Network: "relay", Address: &relay_addr{opkt.priv_hdr.C, ZeroHashname, false}}

		err = h.sw.rcv_pkt(ipkt)
		if err != nil {
			atomic.AddUint64(&h.num_err_pkt_rcv, 1)
			h.log.Noticef("error: %s ipkt=%+v", err, ipkt)
			return
		}

		atomic.AddUint64(&h.num_pkt_rcv, 1)
		h.log.Debugf("rcv-self: %+v %q", opkt.hdr, opkt.body)
		return
	}()
}

func (h *relay_handler) rcv_other(in *pkt_t, to Hashname) {
	line := h.sw.lines[to]
	if line == nil || line.State() != line_opened {
		return // drop
	}

	out := packet_pool_acquire()
	out.priv_hdr.Type = "relay"
	out.priv_hdr.C = in.priv_hdr.C
	out.priv_hdr.To = in.priv_hdr.To
	out.body = buffer_pool_acquire()[:len(in.body)]
	copy(out.body, in.body)

	cmd := cmd_snd_pkt{nil, line, out, true}
	err := cmd.Exec(h.sw)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_rly, 1)
		h.log.Noticef("error: %s out=%+v", err, out)
		return
	}

	atomic.AddUint64(&h.num_pkt_rly, 1)
	h.log.Debugf("rcv-other: %+v %q", out.hdr, out.body)
}

func make_relay_addr() net.Addr {
	c, err := make_hex_rand(16)
	if err != nil {
		return nil
	}

	return &relay_addr{C: c}
}

type relay_addr struct {
	C     string
	via   Hashname
	use_c bool
}

func (n *relay_addr) DefaultPriority() int {
	return 0
}

func (n *relay_addr) PublishWithPath() bool {
	return false
}

func (n *relay_addr) PublishWithPeer() bool {
	return true
}

func (n *relay_addr) PublishWithConnect() bool {
	return false
}

func (n *relay_addr) PublishWithSeek() bool {
	return false
}

func (n *relay_addr) NeedNatHolePunching() bool {
	return false
}

func (r *relay_addr) SeekString() string {
	return ""
}

func (n *relay_addr) SendNatBreaker() bool {
	return false
}

func (n *relay_addr) EqualTo(other net.Addr) bool {
	if o, ok := other.(*relay_addr); ok {
		return o.C == n.C
	}
	return false
}

func (n *relay_addr) String() string {
	return fmt.Sprintf("id=%s via=%s", n.C, n.via.Short())
}

func (h *relay_handler) snd_pkt(sw *Switch, pkt *pkt_t) error {
	var (
		n      = pkt.netpath.Address.(*relay_addr)
		line   *line_t
		routed bool
	)

REROUTE:
	if n.via == ZeroHashname {
		routed = true
		for _, via := range pkt.peer.ViaTable() {
			line := sw.lines[via]
			if line == nil || line.State() != line_opened {
				continue
			}

			path := line.peer.active_path()
			if path == nil || path.Network == "relay" {
				continue
			}

			n.via = via
			break
		}
	}

	if n.via == ZeroHashname {
		return nil // drop
	}

	line = sw.lines[n.via]
	if line == nil || line.State() != line_opened {
		n.via = ZeroHashname
		if routed {
			return nil // drop
		}
		goto REROUTE
	}

	h.log.Noticef("routing %s", n)

	data, err := encode_packet(pkt)
	if err != nil {
		atomic.AddUint64(&h.num_err_pkt_snd, 1)
		h.log.Noticef("error: %s", err)
		buffer_pool_release(data)
		return nil
	}

	opkt := packet_pool_acquire()
	opkt.priv_hdr.Type = "relay"
	opkt.priv_hdr.C = n.C
	opkt.priv_hdr.To = pkt.peer.hashname.String()
	opkt.body = data
	cmd := cmd_snd_pkt{nil, line, opkt, true}
	err = cmd.Exec(h.sw)
	if err != nil {
		n.via = ZeroHashname
		atomic.AddUint64(&h.num_err_pkt_snd, 1)
		h.log.Noticef("error: %s opkt=%+v %q", err, opkt.hdr, opkt.body)
		return err
	}

	atomic.AddUint64(&h.num_pkt_snd, 1)
	h.log.Debugf("snd-self: %+v %q", opkt.hdr, opkt.body)
	return nil
}

func (n *relay_addr) MarshalJSON() ([]byte, error) {
	if n.use_c {
		return json.Marshal(struct {
			Id string `json:"c"`
		}{
			Id: n.C,
		})
	}

	return json.Marshal(struct {
		Id string `json:"id"`
	}{
		Id: n.C,
	})
}

func (n *relay_addr) UnmarshalJSON(data []byte) error {
	var (
		j struct {
			C  string `json:"c"`
			Id string `json:"id"`
		}
	)

	err := json.Unmarshal(data, &j)
	if err != nil {
		return err
	}

	if j.Id == "" && j.C != "" {
		n.use_c = true
		j.Id = j.C
	}

	if j.Id == "" {
		return fmt.Errorf("Invalid relay netpath")
	}

	n.C = j.Id
	return nil
}
