package telehash

import (
	"encoding/hex"
	"github.com/fd/go-util/log"
	"io"
	"runtime/debug"
	"sync"
	"time"
)

type channel_t struct {
	sw                   *Switch
	peer                 *peer_t
	channel_id           string
	channel_type         string
	raw                  bool
	initiator            bool      // is this side of the channel the initiating side?
	broken               bool      // is the channel broken?
	miss                 []seq_t   // missing packets (yet to be received)
	rcv_buf              []*pkt_t  // buffer of unread received packets
	rcv_deadline         time.Time // time after which reads
	rcv_deadline_reached bool      // was the received deadline reached
	rcv_end              bool      // was a `end` packet received?
	rcv_err              string    // the err that was received
	rcv_last_ack         seq_t     // the last `ack` seq received (-1 when no acks have been received)
	rcv_last_ack_at      time.Time // the last time any ack was received
	rcv_last_pkt_at      time.Time // the last time any packet was recieved
	rcv_last_seq         seq_t     // the seq of the last received seq (-1 when no pkts have been received)
	rcv_unacked          int       // number of unacked received packets
	read_end             bool      // did the user read the end packet
	read_last_seq        seq_t     // the last seq that was read by the user code (-1 when no packets were read yet)
	snd_buf              []*pkt_t  // buffer of unacked send packets
	snd_end              bool      // was a `end` packet send?
	snd_end_ack          bool      // was an ack send for the last packet?
	snd_inflight         int       // number of in flight packets
	snd_last_ack         seq_t     // the last `ack` seq send (-1 when no acks have been received)
	snd_last_ack_at      time.Time // the last time any ack was send
	snd_last_pkt_at      time.Time // the last time any packet was send
	snd_last_seq         seq_t     // the seq of the last send packet (-1 when no pkts have been send)
	snd_miss_at          time.Time // the last time the missing packets were sent

	mtx sync.RWMutex
	cnd sync.Cond
	log log.Logger
}

func make_channel(sw *Switch, peer *peer_t, id, typ string, initiator bool, raw bool) (*channel_t, error) {
	c := &channel_t{
		sw:           sw,
		peer:         peer,
		channel_id:   id,
		channel_type: typ,
		raw:          raw,
		initiator:    initiator,
		rcv_buf:      make([]*pkt_t, 0, 100),
	}

	if id == "" {
		bin_id, err := make_rand(16)
		if err != nil {
			return nil, err
		}

		c.channel_id = hex.EncodeToString(bin_id)
	}

	c.log = peer.log.Sub(log_level_for("CHANNEL", log.DEFAULT), "channel["+c.channel_id[:8]+"]")
	c.cnd.L = &c.mtx

	return c, nil
}

// snd_pkt()
// is called by the user code
//
// blocks when
// - there are to many inflight packtes
// - when the other side didn't send the first ack yet
// - when there is no open line yet
//
// does never block when
// - the channel is broken
// - the channel was closed by the other side
// - the channel was closed by this side
func (c *channel_t) snd_pkt(pkt *pkt_t) error {
	var (
		err     error
		blocked bool
	)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if !c.peer.has_open_line() {
		go c.peer.open_line()
	}

	for {
		blocked, err = c._snd_pkt_blocked()
		if err != nil {
			return err
		}
		if !blocked {
			break
		}
		c.cnd.Wait()
	}

	pkt.hdr.C = c.channel_id
	if !c.raw {
		pkt.hdr.Seq = c.snd_last_seq.Incr()
		pkt.hdr.Miss = c.miss
		pkt.hdr.Ack = c.read_last_seq
	}

	c.log.Debugf("snd pkt: hdr=%+v", pkt.hdr)

	err = c.peer.snd_pkt_blocking(pkt)
	if err != nil {
		return err
	}

	now := time.Now()

	if c.rcv_end {
		c.snd_end_ack = true
	}
	if pkt.hdr.End {
		c.snd_end = true
	}
	if !c.raw {
		c.snd_last_ack = pkt.hdr.Ack
		c.snd_last_seq = pkt.hdr.Seq
		c.snd_inflight++
		c.snd_buf = append(c.snd_buf, pkt)
		c.rcv_unacked = 0
		c.snd_last_ack_at = now
	}
	c.snd_last_pkt_at = now

	// state changed
	c.cnd.Broadcast()

	return nil
}

func (c *channel_t) _snd_pkt_blocked() (bool, error) {
	if c.broken || c.rcv_end || c.snd_end {
		// never block when closed
		return false, c._snd_pkt_err()
	}

	if !c.raw {
		if c.snd_inflight >= 100 {
			// wait for progress
			return true, nil
		}

		if c.initiator && c.snd_last_seq.IsSet() && !c.rcv_last_ack.IsSet() {
			// wait for first ack
			return true, nil
		}
	}

	if !c.peer.has_open_line() {
		return true, nil
	}

	return false, nil
}

func (c *channel_t) _snd_pkt_err() error {
	if c.broken {
		return ErrChannelBroken
	}

	if c.rcv_end {
		return ErrSendOnClosedChannel
	}

	if c.snd_end {
		return ErrSendOnClosedChannel
	}

	return nil
}

// snd_ack()
func (c *channel_t) snd_ack() error {
	var (
		err error
		now = time.Now()
	)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.raw {
		return nil
	}

	if !c._needs_auto_ack(now) {
		return nil
	}

	err = c._snd_ack_err()
	if err != nil {
		return err
	}

	pkt := &pkt_t{}
	pkt.hdr.C = c.channel_id
	pkt.hdr.Ack = c.read_last_seq
	pkt.hdr.Miss = c.miss

	c.log.Debugf("snd ack: hdr=%+v", pkt.hdr)

	err = c.peer.snd_pkt(pkt)
	if err != nil {
		return err
	}

	if c.rcv_end {
		c.snd_end_ack = true
	}
	c.rcv_unacked = 0
	c.snd_last_ack_at = now
	c.snd_last_ack = pkt.hdr.Ack

	// state changed
	c.cnd.Broadcast()

	return nil
}

func (c *channel_t) _needs_auto_ack(now time.Time) bool {
	if c.snd_last_ack_at.IsZero() {
		if !c.initiator && c.read_last_seq.IsSet() {
			return true
		} else {
			c.snd_last_ack_at = now
		}
	}

	if c.rcv_end && !c.snd_end_ack {
		return true
	}

	return c.rcv_unacked > 30 || c.snd_last_ack_at.Before(now.Add(-1*time.Second))
}

func (c *channel_t) _snd_ack_err() error {
	if c.broken {
		return ErrChannelBroken
	}

	return nil
}

// push_rcv_pkt()
// called by the peer code
func (c *channel_t) push_rcv_pkt(pkt *pkt_t) error {
	var (
		buf_idx int = -1
		err     error
	)

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if pkt.hdr.Ack.IsSet() {
		// handle ack
		c._rcv_ack(pkt)
	}

	if !pkt.hdr.Seq.IsSet() {
		if c.raw {
			pkt.hdr.Seq = c.rcv_last_seq.Incr()
		} else {
			// pkt is just an ack
			c.log.Debugf("rcv ack: hdr=%+v", pkt.hdr)
			err = nil
			goto EXIT
		}
	}

	if c.snd_end {
		// drop; cannot read packets after having send end
		err = nil
		goto EXIT
	}

	if c.rcv_end && pkt.hdr.Seq > c.rcv_last_seq {
		// drop packet sent after `end`
		err = nil
		goto EXIT
	}

	// check if pkt is a duplicate
	if pkt.hdr.Seq <= c.read_last_seq {
		// already read (duplicate)
		err = errDuplicatePacket
		goto EXIT
	}
	for idx, p := range c.rcv_buf {
		if p.hdr.Seq == pkt.hdr.Seq {
			// already in buffer
			err = errDuplicatePacket
			goto EXIT
		}
		if p.hdr.Seq > pkt.hdr.Seq {
			buf_idx = idx
			break
		}
	}

	c.log.Debugf("rcv pkt: bufferd=%d hdr=%+v", len(c.rcv_buf), pkt.hdr)

	c.rcv_last_pkt_at = time.Now()
	c.rcv_unacked++

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

	// mark the end pkt
	if pkt.hdr.End {
		c.rcv_end = true
		if pkt.hdr.Err != "" {
			c.rcv_err = pkt.hdr.Err
		}
	}

	// record last received seq
	if c.rcv_last_seq < pkt.hdr.Seq {
		c.rcv_last_seq = pkt.hdr.Seq
	}

	c._update_miss_list()

EXIT:

	// state changed
	c.cnd.Broadcast()

	return err
}

func (c *channel_t) _rcv_ack(pkt *pkt_t) {
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

	c.rcv_last_ack_at = time.Now()
	c.snd_inflight = len(snd_buf)

	c.snd_buf = snd_buf
}

func (c *channel_t) _update_miss_list() {
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

func (c *channel_t) pop_rcv_pkt() (*pkt_t, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for {
		blocked, err := c._rcv_blocked()
		if err != nil {
			return nil, err
		}
		if !blocked {
			break
		}
		c.cnd.Wait()
	}

	// pop the packet
	pkt := c.rcv_buf[0]
	copy(c.rcv_buf, c.rcv_buf[1:])
	c.rcv_buf = c.rcv_buf[:len(c.rcv_buf)-1]

	c.read_last_seq = pkt.hdr.Seq

	if pkt.hdr.End {
		c.read_end = true
	}

	// state changed
	c.cnd.Broadcast()

	return pkt, nil
}

func (c *channel_t) _rcv_blocked() (bool, error) {
	if c.broken || c.snd_end || c.read_end || c.rcv_deadline_reached {
		// never block when closed
		return false, c._rcv_err()
	}

	if len(c.rcv_buf) == 0 {
		// wait for progress
		return true, nil
	}

	next_read_seq := c.read_last_seq.Incr()
	if c.rcv_buf[0].hdr.Seq != next_read_seq {
		// wait for progress
		return true, nil
	}

	return false, nil
}

func (c *channel_t) _rcv_err() error {
	if c.rcv_deadline_reached {
		return ErrTimeout
	}

	if c.broken {
		return ErrChannelBroken
	}

	if c.snd_end {
		return ErrReceiveOnClosedChannel
	}

	if c.read_end {
		return io.EOF
	}

	return nil
}

func (c *channel_t) run_user_handler() {
	defer func() {
		c.log.Debug("handler returned: closing channel")

		r := recover()
		if r != nil {
			c.log.Errorf("panic: %s\n%s", r, debug.Stack())
			c.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true, Err: "internal server error"}})
		} else {
			c.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true}})
		}
	}()

	c.sw.mux.serve_telehash(c)
}

func (c *channel_t) set_rcv_deadline(deadline time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.rcv_deadline = deadline
	c.rcv_deadline_reached = false
}

func (c *channel_t) detect_rcv_deadline(now time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.rcv_deadline_reached {
		return
	}

	if c.rcv_deadline.IsZero() {
		return
	}

	if c.rcv_deadline.Before(now) {
		c.rcv_deadline_reached = true
		c.cnd.Broadcast()
	}
}

func (c *channel_t) send_missing_packets(now time.Time) {
	c.mtx.Lock()

	if c.raw {
		c.mtx.Unlock()
		return
	}

	if c.snd_miss_at.After(now.Add(-1 * time.Second)) {
		c.mtx.Unlock()
		return
	}

	c.snd_miss_at = now

	if len(c.snd_buf) == 0 {
		c.mtx.Unlock()
		return
	}

	var (
		buf           = make([]*pkt_t, len(c.snd_buf))
		miss          = make([]seq_t, len(c.miss))
		read_last_seq = c.read_last_seq
	)
	copy(buf, c.snd_buf)
	copy(miss, c.miss)
	c.mtx.Unlock()

	for _, pkt := range buf {
		pkt.hdr.Ack = read_last_seq
		pkt.hdr.Miss = miss
		c.peer.snd_pkt(pkt)
	}
}

func (c *channel_t) is_closed() bool {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.broken {
		return true
	}

	if c.raw && (c.snd_end || c.rcv_end) {
		return true
	}

	// when:
	// - received `end` packet
	// - and there are no missing packets
	// - and there are no inflight packets
	if c.rcv_end && len(c.miss) == 0 && c.snd_inflight == 0 && c.snd_last_ack == c.rcv_last_seq {
		return true
	}

	// when:
	// - send `end` packet
	// - and there are no inflight packets
	if c.snd_end && c.snd_inflight == 0 {
		return true
	}

	return false
}

func (c *channel_t) detect_broken(now time.Time) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	breaking_point := now.Add(-5 * time.Second)

	if c.rcv_last_ack_at.IsZero() {
		c.rcv_last_ack_at = now
	}

	if c.rcv_last_pkt_at.IsZero() {
		c.rcv_last_pkt_at = now
	}

	if c.snd_last_ack_at.IsZero() {
		c.snd_last_ack_at = now
	}

	if c.snd_last_pkt_at.IsZero() {
		c.snd_last_pkt_at = now
	}

	if c.rcv_last_ack_at.Before(breaking_point) && c.rcv_last_pkt_at.Before(breaking_point) ||
		c.snd_last_ack_at.Before(breaking_point) && c.snd_last_pkt_at.Before(breaking_point) {
		c.broken = true
		c.cnd.Broadcast()
	}
}

func (c *channel_t) mark_as_broken() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if !c.broken {
		c.broken = true
		c.cnd.Broadcast()
	}
}
