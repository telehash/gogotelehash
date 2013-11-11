package telehash

import (
	"sync"
	"time"
)

type channel_ack_handler_t struct {
	unacked_count int

	rcv       *channel_rcv_buffer_t
	snd       *channel_snd_buffer_t
	channel   *channel_t
	ack_timer *time.Timer

	mtx sync.RWMutex
	cnd *sync.Cond
}

func make_channel_ack_handler(
	rcv *channel_rcv_buffer_t,
	snd *channel_snd_buffer_t,
	channel *channel_t,
) *channel_ack_handler_t {
	h := &channel_ack_handler_t{rcv: rcv, snd: snd, channel: channel}
	h.cnd = sync.NewCond(&h.mtx)
	return h
}

func (c *channel_ack_handler_t) close() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for c.unacked_count > 0 {
		c.cnd.Wait()
	}

	if c.ack_timer != nil {
		c.ack_timer.Stop()
		c.ack_timer = nil
	}
}

func (c *channel_ack_handler_t) received_packet() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.unacked_count++

	if c.unacked_count > 30 {
		go c._auto_ack()
	} else if c.ack_timer == nil {
		c.ack_timer = time.AfterFunc(1*time.Second, c._auto_ack)
	}

	c.cnd.Broadcast()
}

func (c *channel_ack_handler_t) add_ack_info(pkt *pkt_t) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	ack, miss := c.rcv.inspect()
	if ack >= 0 {
		pkt.hdr.Ack = &ack
		pkt.hdr.Miss = miss
		// Log.Debugf("snd ack=%d miss=%+v", ack, miss)
	}

	c.unacked_count = 0
	if c.ack_timer != nil {
		c.ack_timer.Stop()
		c.ack_timer = nil
	}

	c.cnd.Broadcast()
}

func (c *channel_ack_handler_t) handle_ack_info(pkt *pkt_t) {
	if pkt.hdr.Ack == nil {
		return
	}

	// Log.Debugf("rcv ack=%d miss=%+v", *pkt.hdr.Ack, pkt.hdr.Miss)

	backlog := c.snd.purge_acked(*pkt.hdr.Ack, pkt.hdr.Miss)

	ack, miss := c.rcv.inspect()

	for _, pkt := range backlog {
		if ack >= 0 {
			pkt.hdr.Ack = &ack
			pkt.hdr.Miss = miss
			// Log.Debugf("snd ack=%d miss=%+v", ack, miss)
		}

		err := c.channel.sw.net.snd_pkt(c.channel.peer, pkt)
		if err != nil {
			Log.Debugf("error while resending pkt: %s", err)
		}
	}
}

func (c *channel_ack_handler_t) _auto_ack() {
	pkt := &pkt_t{hdr: pkt_hdr_t{C: c.channel.id}}

	c.add_ack_info(pkt)

	err := c.channel.sw.net.snd_pkt(c.channel.peer, pkt)
	if err != nil {
		Log.Debugf("error while sending auto ack: %s (%+v)", err, pkt.hdr)
	}
}
