package telehash

import (
	"io"
	"sort"
	"sync"
)

type channel_snd_buffer_t struct {
	next_seq     int
	max_seq      int
	last_ack     int
	buf          []*pkt_t
	inflight     int
	send_end_pkt bool

	mtx sync.RWMutex
	cnd *sync.Cond
}

func make_channel_snd_buffer() *channel_snd_buffer_t {
	b := &channel_snd_buffer_t{
		buf: make([]*pkt_t, 0, 100),
	}

	b.cnd = sync.NewCond(&b.mtx)

	return b
}

func (c *channel_snd_buffer_t) purge_acked(ack int, miss []int) []*pkt_t {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// set last ack
	if c.last_ack < ack {
		c.last_ack = ack
	}

	// process misses
	sort.Ints(miss)

	var (
		new_buf  = make([]*pkt_t, 0, len(c.buf))
		queue    = make([]*pkt_t, 0, len(c.buf))
		miss_idx = 0
		inflight = 0
	)

	for _, pkt := range c.buf {
		if pkt.hdr.Seq > ack {
			// unconfirmed pkt
			new_buf = append(new_buf, pkt)
			inflight++

		} else if len(miss) > miss_idx {
			if pkt.hdr.Seq == miss[miss_idx] {
				// missed pkt
				new_buf = append(new_buf, pkt)
				miss_idx++
				queue = append(queue, pkt)
				inflight++

			} else if pkt.hdr.Seq > miss[miss_idx] {
				// we know this miss was already acked
				miss_idx++

			}
		}
		// else acked
	}

	c.inflight = inflight
	c.buf = new_buf

	// notify senders
	c.cnd.Signal()

	return queue
}

func (c *channel_snd_buffer_t) put(pkt *pkt_t) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// block until the buffer is not full
	for !c._send_more() && !c._ended() {
		c.cnd.Wait()
	}

	if c.send_end_pkt {
		return io.EOF
	}

	if pkt.hdr.End {
		c.send_end_pkt = true
	}

	// set the next seq
	pkt.hdr.Seq = c.next_seq
	c.next_seq++

	c.inflight++

	c.buf = append(c.buf, pkt)

	// notify other senders
	c.cnd.Signal()

	// Log.Debugf("snd  pkt seq=%d", pkt.hdr.Seq)

	return nil
}

func (c *channel_snd_buffer_t) _send_more() bool {
	return c.inflight < 100
}

func (c *channel_snd_buffer_t) _ended() bool {
	return c.send_end_pkt
}
