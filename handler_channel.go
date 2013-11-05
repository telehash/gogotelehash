package telehash

import (
	"crypto/rsa"
	"encoding/hex"
	"sync"
	"time"
)

type channel_t struct {
	conn *channel_handler

	id           string // id of the channel
	peer         string // hashname of the peer
	channel_type string // type of the channel
	snd_init_pkt bool
	snd_seq_next int
	snd_in_flght int
	snd_buf      map[int]*pkt_t
	rcv_init_ack bool
	end          bool
	rcv_seq_next int
	rcv_seq_last int
	rcv_ack_last int
	rcv_buf      map[int]*pkt_t

	readable_pkt *pkt_t

	i_queue    chan *pkt_t
	s_queue    chan channel_handler_snd
	r_queue    chan *pkt_t
	a_ticker   *time.Ticker
	r_deadline *time.Timer
	need_ack   bool
}

type channel_handler_iface interface {
	serve_telehash(channel *channel_t)
}

type channel_handler_func func(channel *channel_t)

func (f channel_handler_func) serve_telehash(channel *channel_t) {
	f(channel)
}

type channel_handler struct {
	conn         *line_handler
	peers        *peer_handler
	channels     map[string]*channel_t
	channels_mtx sync.Mutex
	handler      channel_handler_iface
}

type channel_handler_snd struct {
	pkt   *pkt_t
	reply chan error
}

func (h *channel_handler) reader_loop() {
	defer func() {
		for _, c := range h.channels {
			c.close_with_error("switch was terminated")
		}
	}()

	for pkt := range h.conn.rcv {
		h.rcv_channel_pkt(pkt)
	}
}

func channel_handler_open(addr string, prvkey *rsa.PrivateKey, handler channel_handler_iface, peers *peer_handler) (*channel_handler, error) {
	conn, err := line_handler_open(addr, prvkey, peers)
	if err != nil {
		return nil, err
	}

	h := &channel_handler{
		conn:     conn,
		peers:    peers,
		channels: make(map[string]*channel_t),
		handler:  handler,
	}

	go h.reader_loop()

	return h, nil
}

func (h *channel_handler) close() {
	h.conn.close()
}

func (h *channel_handler) open_channel(hashname string, pkt *pkt_t) (*channel_t, error) {
	id, err := make_rand(16)
	if err != nil {
		return nil, err
	}

	channel := h.make_channel(hashname)
	channel.id = hex.EncodeToString(id)
	h.add_channel(channel)

	go channel.control_loop()

	err = channel.send(pkt)
	if err != nil {
		channel.close()
		return nil, err
	}

	return channel, nil
}

func (h *channel_handler) add_channel(c *channel_t) {
	h.channels_mtx.Lock()
	defer h.channels_mtx.Unlock()

	h.channels[c.id] = c
}

func (h *channel_handler) drop_channel(c *channel_t) {
	h.channels_mtx.Lock()
	defer h.channels_mtx.Unlock()

	delete(h.channels, c.id)
}

func (h *channel_handler) make_channel(peer string) *channel_t {
	c := &channel_t{
		conn:         h,
		peer:         peer,
		rcv_ack_last: -1,
		snd_buf:      make(map[int]*pkt_t, 16),
		rcv_buf:      make(map[int]*pkt_t, 16),
		i_queue:      make(chan *pkt_t, 1),
		r_queue:      make(chan *pkt_t),
		s_queue:      make(chan channel_handler_snd),
		a_ticker:     time.NewTicker(250 * time.Microsecond),
		r_deadline:   time.NewTimer(10 * time.Second),
	}

	c.r_deadline.Stop()

	return c
}

func (c *channel_t) control_loop() {
	for {
		var (
			s_queue = c.s_queue
			a_queue = c.a_ticker.C
			i_queue = c.i_queue
			r_queue = c.r_queue
		)

		// don't send new packets when there are more than a 100 in-flight packets
		if c.snd_in_flght > 100 {
			s_queue = nil
		}

		// don't read new packets unles a packet is ready
		if c.readable_pkt == nil {
			r_queue = nil
		}

		// only allow sending packets
		if !c.snd_init_pkt {
			a_queue = nil
			r_queue = nil
			i_queue = nil
		} else if !c.rcv_init_ack {
			// only allow receiving acks
			a_queue = nil
			r_queue = nil
			s_queue = nil
		}

		select {
		case <-c.r_deadline.C:
			c.rcv_pkt(&pkt_t{
				hdr: pkt_hdr_t{
					C:   c.id,
					Seq: c.rcv_seq_next,
					End: true,
					Err: "timeout",
				},
			})
		case <-a_queue:
			c.send_ack()
		case r_queue <- c.readable_pkt:
			// remove from buffer
			delete(c.rcv_buf, c.readable_pkt.hdr.Seq)
			c.readable_pkt = nil

			// prepare new pkt
			c.rcv_seq_next++
			if pkt := c.rcv_buf[c.rcv_seq_next]; pkt != nil {
				c.readable_pkt = pkt
			}

		case pkt := <-i_queue:
			c.rcv_pkt(pkt)
		case cmd := <-s_queue:
			c.snd_pkt(cmd)
		}
	}
}

func (c *channel_t) SetReceiveDeadline(deadline time.Time) {
	c.r_deadline.Reset(deadline.Sub(time.Now()))
}

func (c *channel_t) close() error {
	return c.close_with_error("")
}

func (c *channel_t) close_with_error(err string) error {
	defer c.conn.drop_channel(c)

	if c.end {
		return nil
	}

	return c.send(&pkt_t{hdr: pkt_hdr_t{End: true, Err: err}})
}

func (c *channel_t) send(pkt *pkt_t) error {
	reply := make(chan error, 1)
	c.s_queue <- channel_handler_snd{pkt, reply}
	return <-reply
}

func (c *channel_t) receive() (*pkt_t, error) {
	return <-c.r_queue, nil
}

func (c *channel_t) snd_pkt(cmd channel_handler_snd) {
	// mark the packet
	cmd.pkt.hdr.C = c.id

	// buffer the backet
	cmd.pkt.hdr.Seq = c.snd_seq_next
	c.snd_buf[cmd.pkt.hdr.Seq] = cmd.pkt
	c.snd_seq_next++

	// send pkt
	// Log.Debugf("channel[%s]: snd %+v", c.id[:8], cmd.pkt)
	err := c.conn.conn.send(c.peer, cmd.pkt)
	if err != nil {
		cmd.reply <- err
		return
	}
	cmd.reply <- nil

	c.snd_in_flght++

	if !c.snd_init_pkt {
		c.snd_init_pkt = true
	}
}

func (c *channel_t) rcv_pkt(pkt *pkt_t) {
	// Log.Debugf("channel[%s]: rcv %+v", c.id[:8], pkt)

	// Step 1:
	// - handle ack
	if pkt.hdr.Ack != nil {
		c.handle_ack(pkt)
		return
	}

	// Step 3:
	// - handle rcv
	c.buffer_pkt(pkt)
}

func (c *channel_t) handle_ack(pkt *pkt_t) {
	var (
		ack    = *pkt.hdr.Ack
		missed = make(map[int]bool, len(pkt.hdr.Miss))
	)

	if ack < c.rcv_ack_last {
		// drop ack;
		return
	}
	c.rcv_ack_last = ack
	c.snd_in_flght = c.snd_seq_next - 1 - ack + len(pkt.hdr.Miss)

	// Log.Debugf("channel[%s]: rcv ack=%d in-flight=%d missing=%+v", c.id[:8], ack, c.snd_in_flght, pkt.hdr.Miss)

	// resend missed packets
	if len(pkt.hdr.Miss) > 0 {
		for _, seq := range pkt.hdr.Miss {
			if pkt := c.snd_buf[seq]; pkt != nil {
				c.conn.conn.send(c.peer, pkt)
			}
		}
	}

	// clean buffer
	for seq := range c.snd_buf {
		if seq <= ack && !missed[seq] {
			delete(c.snd_buf, seq)
		}
	}

	if !c.rcv_init_ack {
		c.rcv_init_ack = true
	}
}

func (c *channel_t) buffer_pkt(pkt *pkt_t) {
	if c.rcv_buf[pkt.hdr.Seq] != nil {
		// drop pkt; already received
		return
	}

	if c.rcv_seq_last < pkt.hdr.Seq {
		if c.end {
			// drop pkt; pkt.Seq is larger than the end pkt
			return
		}
		c.rcv_seq_last = pkt.hdr.Seq
	}

	if pkt.hdr.End {
		c.end = true
	}

	if c.rcv_seq_next == pkt.hdr.Seq {
		c.readable_pkt = pkt
	}

	c.rcv_buf[pkt.hdr.Seq] = pkt
	c.request_ack()
}

func (c *channel_t) request_ack() {
	c.need_ack = true
}

func (c *channel_t) send_ack() {
	if !c.need_ack {
		return
	}
	c.need_ack = false

	var (
		missing []int
		ack     = new(int)
	)

	*ack = c.rcv_seq_last

	for i := c.rcv_seq_next; i < c.rcv_seq_last; i++ {
		if c.rcv_buf[i] == nil {
			// missing
			missing = append(missing, i)
		}
	}

	pkt := &pkt_t{
		hdr: pkt_hdr_t{
			C:    c.id,
			Ack:  ack,
			Miss: missing,
		},
	}

	// Log.Debugf("channel[%s]: snd ack=%d missing=%+v", c.id[:8], *ack, missing)
	err := c.conn.conn.send(c.peer, pkt)
	if err != nil {
		// Log.Debugf("channel[%s]: snd-ack err=%s", c.id[:8], err)
	}
}

func (h *channel_handler) rcv_channel_pkt(pkt *pkt_t) {
	if pkt.hdr.C == "" {
		return // drop; unknown channel
	}

	// Log.Debugf("channel[%s]: rcv %+v", pkt.hdr.C[:8], pkt)

	channel := h.channels[pkt.hdr.C]
	if channel == nil {
		if pkt.hdr.Type != "" {
			h.rcv_new_channel_pkt(pkt)
			return
		} else {
			return // drop; unknown channel
		}
	}

	channel.i_queue <- pkt
}

func (h *channel_handler) rcv_new_channel_pkt(pkt *pkt_t) {
	channel := h.make_channel(pkt.peer)
	channel.id = pkt.hdr.C
	channel.channel_type = pkt.hdr.Type
	channel.snd_init_pkt = true
	channel.rcv_init_ack = true
	h.add_channel(channel)

	go channel.control_loop()
	go channel.run_user_handler()

	channel.i_queue <- pkt
}

func (c *channel_t) run_user_handler() {
	defer c.close()
	defer func() {
		r := recover()
		if r != nil {
			Log.Error(r)
			c.close_with_error("internal server error")
		}
	}()

	c.conn.handler.serve_telehash(c)
}
