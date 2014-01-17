package telehash

import (
	"time"
)

type channel_reliable_t struct {
	line            *line_t
	channel         *Channel
	miss            []seq_t   // missing packets (yet to be received)
	rcv_buf         []*pkt_t  // buffer of unread received packets
	rcv_last_ack    seq_t     // the last `ack` seq received (-1 when no acks have been received)
	rcv_last_ack_at time.Time // the last time any ack was received
	rcv_last_pkt_at time.Time // the last time any packet was recieved
	rcv_last_seq    seq_t     // the seq of the last received seq (-1 when no pkts have been received)
	rcv_unacked     int       // number of unacked received packets
	read_last_seq   seq_t     // the last seq that was read by the user code (-1 when no packets were read yet)
	snd_first_pkt   bool      // was the first pkt already send?
	snd_buf         []*pkt_t  // buffer of unacked send packets
	snd_end_ack     bool      // was an ack send for the last packet?
	snd_inflight    int       // number of in flight packets
	snd_last_ack    seq_t     // the last `ack` seq send (-1 when no acks have been received)
	snd_last_ack_at time.Time // the last time any ack was send
	snd_last_pkt_at time.Time // the last time any packet was send
	snd_last_seq    seq_t     // the seq of the last send packet (-1 when no pkts have been send)
	snd_miss_at     time.Time // the last time the missing packets were sent
	ack_timer       *time.Timer
	miss_timer      *time.Timer
}

func make_channel_reliable(line *line_t, channel *Channel) (channel_imp, error) {
	c := &channel_reliable_t{
		line:    line,
		channel: channel,
		rcv_buf: make([]*pkt_t, 0, 100),
	}

	return c, nil
}

func (c *channel_reliable_t) can_snd_pkt() bool {
	if c.line.State() == line_closed {
		return true
	}

	if c.line.State() != line_opened {
		return false
	}

	if c.snd_inflight >= 100 {
		// wait for progress
		return false
	}

	if c.channel.initiator && c.snd_last_seq.IsSet() && !c.rcv_last_ack.IsSet() {
		// wait for first ack
		return false
	}

	return true
}

func (c *channel_reliable_t) will_send_packet(pkt *pkt_t) error {

	if c.line.State() == line_closed {
		return ErrPeerBroken
	}

	pkt.hdr.Seq = c.snd_last_seq.Incr()
	pkt.hdr.Miss = c.miss
	pkt.hdr.Ack = c.read_last_seq
	if !c.snd_first_pkt {
		c.snd_first_pkt = true
		if c.channel.initiator {
			pkt.hdr.Type = c.channel.options.Type
		}
	}

	return nil
}

func (c *channel_reliable_t) did_send_packet(pkt *pkt_t) {
	now := time.Now()

	if c.channel.rcv_end {
		c.snd_end_ack = true
	}
	c.snd_last_ack = pkt.hdr.Ack
	c.snd_last_seq = pkt.hdr.Seq
	c.snd_inflight++
	c.snd_buf = append(c.snd_buf, pkt)
	c.rcv_unacked = 0
	c.snd_last_ack_at = now
	c.snd_last_pkt_at = now

	if c.ack_timer != nil {
		c.ack_timer.Reset(time.Second)
	}
}

// push_rcv_pkt()
// called by the peer code
func (c *channel_reliable_t) push_rcv_pkt(pkt *pkt_t) error {
	var (
		buf_idx int = -1
	)

	if pkt.hdr.Ack.IsSet() {
		// handle ack
		c._rcv_ack(pkt)
	}

	if !pkt.hdr.Seq.IsSet() {
		// pkt is just an ack
		// c.log.Debugf("rcv ack: hdr=%+v", pkt.hdr)
		return nil
	}

	if c.channel.snd_end {
		// drop; cannot read packets after having send end
		return nil
	}

	if len(c.rcv_buf) >= 100 {
		// drop packet when buffer is full
		return nil
	}

	if c.channel.rcv_end && pkt.hdr.Seq > c.rcv_last_seq {
		// drop packet sent after `end`
		return nil
	}

	// check if pkt is a duplicate
	if pkt.hdr.Seq <= c.read_last_seq {
		// already read (duplicate)
		return errDuplicatePacket
	}
	for idx, p := range c.rcv_buf {
		if p.hdr.Seq == pkt.hdr.Seq {
			// already in buffer
			return errDuplicatePacket
		}
		if p.hdr.Seq > pkt.hdr.Seq {
			buf_idx = idx
			break
		}
	}

	c.rcv_last_pkt_at = time.Now()

	// add pkt to buffer
	if buf_idx == -1 {
		c.rcv_buf = append(c.rcv_buf, pkt)
	} else {
		rcv_buf := c.rcv_buf
		rcv_buf = rcv_buf[:len(rcv_buf)+1]
		copy(rcv_buf[buf_idx+1:], rcv_buf[buf_idx:])
		rcv_buf[buf_idx] = pkt
		c.rcv_buf = rcv_buf
	}

	// record last received seq
	if c.rcv_last_seq < pkt.hdr.Seq {
		c.rcv_last_seq = pkt.hdr.Seq
	}

	c._update_miss_list()

	return nil
}

func (c *channel_reliable_t) _rcv_ack(pkt *pkt_t) {
	if pkt.hdr.Ack > c.rcv_last_ack {
		c.rcv_last_ack = pkt.hdr.Ack
	}

	snd_buf := make([]*pkt_t, 0, 100)

	for _, p := range c.snd_buf {
		if p.hdr.Seq > pkt.hdr.Ack {
			// not acked yet keep in buffer
			snd_buf = append(snd_buf, p)
			continue
		}

		for _, missed := range pkt.hdr.Miss {
			if p.hdr.Seq == missed {
				// missing keep
				snd_buf = append(snd_buf, p)
				break
			}
		}

		// other wise drop
	}

	if len(snd_buf) > 0 && c.miss_timer == nil {
		c.channel.sw.reactor.CastAfter(100*time.Millisecond, &cmd_channel_snd_miss{c.channel, c})
	}

	c.rcv_last_ack_at = time.Now()
	c.snd_inflight = len(snd_buf)
	c.snd_buf = snd_buf
}

func (c *channel_reliable_t) _update_miss_list() {
	c.miss = c.miss[:0]

	n := len(c.rcv_buf)
	last := c.read_last_seq.Incr() // last unknown seq

	for i := n - 1; i >= 0; i-- {
		next := c.rcv_buf[i].hdr.Seq
		for j := last; j < next; j = j.Incr() {
			c.miss = append(c.miss, j)
		}
		last = next.Incr()
	}
}

func (c *channel_reliable_t) can_pop_rcv_pkt() bool {

	if len(c.rcv_buf) == 0 {
		return false
	}

	if c.rcv_buf[0].hdr.Seq == c.read_last_seq.Incr() {
		return true
	}

	return false
}

func (c *channel_reliable_t) pop_rcv_pkt() (*pkt_t, error) {
	if len(c.rcv_buf) == 0 {
		return nil, nil
	}

	// pop the packet
	pkt := c.rcv_buf[0]
	copy(c.rcv_buf, c.rcv_buf[1:])
	c.rcv_buf = c.rcv_buf[:len(c.rcv_buf)-1]

	c.read_last_seq = pkt.hdr.Seq
	c.rcv_unacked++

	if c.ack_timer == nil {
		c.ack_timer = c.channel.sw.reactor.CastAfter(time.Second, &cmd_channel_ack{c.channel, c})
	}

	if c.rcv_unacked > 30 {
		c.channel.sw.reactor.Cast(&cmd_channel_ack{c.channel, c})
	} else if c.snd_last_ack_at.IsZero() {
		if !c.channel.initiator && c.read_last_seq.IsSet() {
			c.channel.sw.reactor.Cast(&cmd_channel_ack{c.channel, c})
		} else {
			c.snd_last_ack_at = time.Now()
		}
	}

	return pkt, nil
}

func (c *channel_reliable_t) _get_missing_packets(now time.Time) []*pkt_t {
	if c.snd_miss_at.After(now.Add(-1 * time.Second)) {
		return nil
	}

	c.snd_miss_at = now

	if len(c.snd_buf) == 0 {
		return nil
	}

	var (
		buf           = make([]*pkt_t, len(c.snd_buf))
		miss          = make([]seq_t, len(c.miss))
		read_last_seq = c.read_last_seq
	)
	copy(buf, c.snd_buf)
	copy(miss, c.miss)

	for _, pkt := range buf {
		pkt.hdr.Ack = read_last_seq
		pkt.hdr.Miss = miss
	}

	return buf
}

func (i *channel_reliable_t) is_closed() bool {

	// when:
	// - received `end` packet
	// - and there are no missing packets
	// - and there are no inflight packets
	if i.channel.rcv_end && len(i.miss) == 0 && i.snd_inflight == 0 && i.snd_last_ack == i.rcv_last_seq {
		return true
	}

	// when:
	// - send `end` packet
	// - and there are no inflight packets
	if i.channel.snd_end && i.snd_inflight == 0 {
		return true
	}

	return false
}

type cmd_channel_ack struct {
	channel *Channel
	imp     *channel_reliable_t
}

func (cmd *cmd_channel_ack) Exec(sw *Switch) error {
	var (
		channel = cmd.channel
		imp     = cmd.imp
	)

	pkt := &pkt_t{}
	pkt.hdr.C = channel.options.Id
	pkt.hdr.Ack = imp.read_last_seq
	pkt.hdr.Miss = make([]seq_t, len(imp.miss))
	copy(pkt.hdr.Miss, imp.miss)

	{
		cmd := cmd_snd_pkt{nil, channel.line, pkt}
		cmd.Exec(sw) // do we care about err?
	}

	if channel.rcv_end {
		imp.snd_end_ack = true
	}

	imp.rcv_unacked = 0
	imp.snd_last_ack_at = time.Now()
	imp.snd_last_ack = pkt.hdr.Ack

	imp.ack_timer.Reset(time.Second)
	return nil
}

type cmd_channel_snd_miss struct {
	channel *Channel
	imp     *channel_reliable_t
}

func (cmd *cmd_channel_snd_miss) Exec(sw *Switch) error {
	var (
		channel = cmd.channel
		imp     = cmd.imp
		snd_buf []*pkt_t
	)

	imp.miss_timer = nil

	snd_buf = make([]*pkt_t, len(imp.snd_buf))
	copy(snd_buf, imp.snd_buf)

	for _, pkt := range snd_buf {
		cmd := cmd_snd_pkt{nil, channel.line, pkt}
		cmd.Exec(sw) // do we care about err?
	}

	return nil
}
