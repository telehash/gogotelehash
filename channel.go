package telehash

import (
	"encoding/json"
	"time"
)

type Channel struct {
	id           string
	peer         *peer_t
	snd_init_pkt bool
	snd_seq_next int
	snd_in_flght int
	snd_buf      map[int]*pkt_t
	rcv_init_ack bool
	rcv_end      bool
	rcv_seq_next int
	rcv_seq_last int
	rcv_ack_last int
	rcv_buf      map[int]*pkt_t

	readable_pkt *pkt_t

	i_queue  chan *pkt_t
	s_queue  chan channel_command_i
	r_queue  chan *pkt_t
	a_ticker *time.Ticker
	need_ack bool
}

type channel_command_i interface {
	exec(c *Channel)
}

func make_channel(peer *peer_t) *Channel {
	c := &Channel{
		peer:         peer,
		rcv_ack_last: -1,
		snd_buf:      make(map[int]*pkt_t, 16),
		rcv_buf:      make(map[int]*pkt_t, 16),
		i_queue:      make(chan *pkt_t, 1),
		r_queue:      make(chan *pkt_t),
		s_queue:      make(chan channel_command_i),
		a_ticker:     time.NewTicker(250 * time.Microsecond),
	}

	return c
}

func (c *Channel) control_loop() {
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
			c.handle_pkt(pkt)
		case cmd := <-s_queue:
			cmd.exec(c)
		}
	}
}

func (c *Channel) Send(hdr interface{}, body []byte) error {
	pkt := &pkt_t{}

	if hdr != nil {
		custom, err := json.Marshal(hdr)
		if err != nil {
			return err
		}
		pkt.hdr.Custom = json.RawMessage(custom)
	}

	pkt.body = body

	return c.send(pkt)
}

func (c *Channel) Receive(hdr interface{}) (body []byte, err error) {
	pkt, err := c.receive()
	if err != nil {
		return nil, err
	}

	if len(pkt.hdr.Custom) > 0 {
		err = json.Unmarshal([]byte(pkt.hdr.Custom), hdr)
		if err != nil {
			return nil, err
		}
	}

	return pkt.body, nil
}

func (c *Channel) Close() error {
	return nil
}

func (c *Channel) send(pkt *pkt_t) error {
	c.s_queue <- &cmd_pkt_send{pkt}
	return nil
}

func (c *Channel) receive() (*pkt_t, error) {
	return <-c.r_queue, nil
}

func (c *Channel) handle_pkt(pkt *pkt_t) {
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

func (c *Channel) handle_ack(pkt *pkt_t) {
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

	Log.Debugf("channel[%s]: rcv ack=%d in-flight=%d missing=%+v", c.id, ack, c.snd_in_flght, pkt.hdr.Miss)

	// resend missed packets
	if len(pkt.hdr.Miss) > 0 {
		line := c.peer.get_line()
		for _, seq := range pkt.hdr.Miss {
			if pkt := c.snd_buf[seq]; pkt != nil {
				line.send_pkt(pkt)
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

func (c *Channel) buffer_pkt(pkt *pkt_t) {
	if c.rcv_buf[pkt.hdr.Seq] != nil {
		// drop pkt; already received
		return
	}

	if c.rcv_seq_last < pkt.hdr.Seq {
		if c.rcv_end {
			// drop pkt; pkt.Seq is larger than the end pkt
			return
		}
		c.rcv_seq_last = pkt.hdr.Seq
	}

	if pkt.hdr.End {
		c.rcv_end = true
	}

	if c.rcv_seq_next == pkt.hdr.Seq {
		c.readable_pkt = pkt
	}

	c.rcv_buf[pkt.hdr.Seq] = pkt
	c.request_ack()
}

func (c *Channel) request_ack() {
	c.need_ack = true
}

func (c *Channel) send_ack() {
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

	Log.Debugf("channel[%s]: snd ack=%d missing=%+v", c.id, *ack, missing)
	c.peer.get_line().send_pkt(pkt)
}

type cmd_pkt_send struct {
	pkt *pkt_t
}

func (cmd *cmd_pkt_send) exec(c *Channel) {
	// mark the packet
	cmd.pkt.hdr.C = c.id

	// buffer the backet
	cmd.pkt.hdr.Seq = c.snd_seq_next
	c.snd_buf[cmd.pkt.hdr.Seq] = cmd.pkt
	c.snd_seq_next++

	// send the packet
	c.peer.get_line().send_pkt(cmd.pkt)

	c.snd_in_flght++

	if !c.snd_init_pkt {
		c.snd_init_pkt = true
	}
}
