package telehash

import (
	"time"
)

type channel_stateless_t struct {
	line            *line_t
	channel         *Channel
	rcv_buf         []*pkt_t  // buffer of unread received packets
	rcv_last_pkt_at time.Time // the last time any packet was recieved
	snd_last_pkt_at time.Time // the last time any packet was send
}

func make_channel_stateless(line *line_t, channel *Channel) (channel_imp, error) {
	c := &channel_stateless_t{
		line:    line,
		channel: channel,
		rcv_buf: make([]*pkt_t, 0, 100),
	}

	return c, nil
}

func (c *channel_stateless_t) can_snd_pkt() bool {
	if c.line.State() == line_closed {
		return true
	}

	if c.line.State() != line_opened {
		return false
	}

	return true
}

func (c *channel_stateless_t) will_send_packet(pkt *pkt_t) error {
	if c.line.State() == line_closed {
		return ErrPeerBroken
	}

	pkt.hdr.Type = c.channel.options.Type

	return nil
}

func (c *channel_stateless_t) did_send_packet(pkt *pkt_t) {
	c.snd_last_pkt_at = time.Now()
}

// push_rcv_pkt()
// called by the peer code
func (c *channel_stateless_t) push_rcv_pkt(pkt *pkt_t) error {
	var (
		err error
	)

	if pkt.hdr.Ack.IsSet() {
		// should not have ack
		err = errInvalidPkt
		goto EXIT
	}

	if pkt.hdr.Seq.IsSet() {
		// should not have seq
		err = errInvalidPkt
		goto EXIT
	}

	if c.channel.snd_end {
		// drop; cannot read packets after having send end
		err = nil
		goto EXIT
	}

	if len(c.rcv_buf) >= 100 {
		// drop packet when buffer is full
		err = nil
		goto EXIT
	}

	if c.channel.rcv_end {
		// drop packet sent after `end`
		err = nil
		goto EXIT
	}

	c.rcv_last_pkt_at = time.Now()

	// add pkt to buffer
	c.rcv_buf = append(c.rcv_buf, pkt)

EXIT:

	return err
}

func (c *channel_stateless_t) can_pop_rcv_pkt() bool {
	if len(c.rcv_buf) == 0 {
		return false
	}

	return true
}

func (c *channel_stateless_t) pop_rcv_pkt() (*pkt_t, error) {

	// pop the packet
	pkt := c.rcv_buf[0]
	copy(c.rcv_buf, c.rcv_buf[1:])
	c.rcv_buf = c.rcv_buf[:len(c.rcv_buf)-1]

	return pkt, nil
}

// func (c *channel_stateless_t) tick(now time.Time) (ack *pkt_t, miss []*pkt_t) {
//   var (
//     err error
//   )

//   c._detect_broken(now)

//   return nil, nil
// }

// func (c *channel_stateless_t) _detect_broken(now time.Time) {
//   breaking_point := now.Add(-60 * time.Second)

//   if c.rcv_last_pkt_at.IsZero() {
//     c.rcv_last_pkt_at = now
//   }

//   if c.snd_last_pkt_at.IsZero() {
//     c.snd_last_pkt_at = now
//   }

//   if c.rcv_last_pkt_at.Before(breaking_point) || c.snd_last_pkt_at.Before(breaking_point) {
//     c.broken = true
//   }
// }

func (i *channel_stateless_t) is_closed() bool {

	if i.channel.snd_end || i.channel.rcv_end {
		return true
	}

	return false
}
