package telehash

import (
	"io"
	"sort"
	"sync"
)

type channel_snd_buffer_t struct {
	ch               *channel_t
	next_seq         int
	max_seq          int
	last_ack         int
	buf              []*pkt_t
	inflight         int
	send_end_pkt     bool
	received_end_pkt bool

	mtx sync.RWMutex
	cnd *sync.Cond
}

func make_channel_snd_buffer(ch *channel_t) *channel_snd_buffer_t {
	b := &channel_snd_buffer_t{
		ch:  ch,
		buf: make([]*pkt_t, 0, 100),
	}

	b.cnd = sync.NewCond(&b.mtx)

	return b
}

func (c *channel_snd_buffer_t) send_end() bool {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	return c.send_end_pkt
}

func (c *channel_snd_buffer_t) close() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for !c._ended_and_idle() && !c.received_end_pkt {
		c.cnd.Wait()
	}

	// notify senders
	c.cnd.Broadcast()
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
	c.cnd.Broadcast()

	return queue
}

func (c *channel_snd_buffer_t) put(pkt *pkt_t) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// block until the buffer is not full
	for !c._send_more() && !c._ended() && !c.received_end_pkt {
		c.cnd.Wait()
	}

	if c.send_end_pkt || c.received_end_pkt {
		return io.EOF
	}

	if pkt.hdr.End {
		c.send_end_pkt = true
		if c.ch != nil {
			c.ch.rcv.end_pkt_was_send()
		}
	}

	// set the next seq
	pkt.hdr.Seq = c.next_seq
	c.next_seq++

	c.inflight++

	c.buf = append(c.buf, pkt)

	// notify other senders
	c.cnd.Broadcast()

	// Log.Debugf("snd  pkt seq=%d", pkt.hdr.Seq)

	return nil
}

func (c *channel_snd_buffer_t) end_pkt_was_received() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.received_end_pkt = true
	c.cnd.Broadcast()
}

func (c *channel_snd_buffer_t) _idle() bool {
	return c.inflight == 0
}

func (c *channel_snd_buffer_t) _send_more() bool {
	return c.inflight < 100
}

func (c *channel_snd_buffer_t) _ended() bool {
	return c.send_end_pkt
}

func (c *channel_snd_buffer_t) _ended_and_idle() bool {
	return c._idle() && c._ended()
}
