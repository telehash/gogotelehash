package telehash

import (
	"errors"
	"time"
)

type rawChannel struct {
	id                   string
	line                 *line_t
	snd_chan             chan cmd_channel_snd
	rcv_chan_i           chan *pkt_t          // net facing
	rcv_chan_o           chan cmd_channel_rcv // user facing
	rcv_pkt_buf          *pkt_t
	rcv_err              error
	rcv_deadline         *time.Timer
	rcv_deadline_set     chan time.Time
	rcv_deadline_reached bool
	close_chan           chan cmd_channel_close
	close_cmd            cmd_channel_close
	state                channel_state
}

type (
	cmd_channel_snd struct {
		pkt   *pkt_t
		reply chan error
	}

	cmd_channel_rcv struct {
		pkt *pkt_t
		err error
	}

	cmd_channel_close struct {
		reply chan error
	}
)

func (c *rawChannel) run_main_loop() {
	c.setup()
	defer c.teardown()

	for c.state.test(channel_running, 0) {
		switch {

		case c.state.test(channel_snd_end, 0):
			c.run_terminating_snd_end_loop()

		case c.state.test(channel_rcv_end, 0):
			c.run_terminating_rcv_end_loop()

		case c.state.test(channel_open, 0):
			c.run_open_loop()

		}
	}
}

func (c *rawChannel) run_open_loop() {
	for c.state.test(channel_open, 0) {
		var (
			rcv_chan_o        chan cmd_channel_rcv
			rcv_deadline_chan <-chan time.Time
			rcv_cmd           cmd_channel_rcv
		)

		if c.rcv_pkt_buf != nil || c.rcv_deadline_reached {
			rcv_chan_o = c.rcv_chan_o

			if c.rcv_deadline_reached {
				rcv_cmd.pkt = c.rcv_pkt_buf
				rcv_cmd.err = nil
			} else {
				rcv_cmd.pkt = nil
				rcv_cmd.err = ErrTimeout
			}
		}

		if c.rcv_deadline != nil {
			rcv_deadline_chan = c.rcv_deadline.C
		}

		select {

		case <-rcv_deadline_chan:
			c.rcv_deadline_reached = true

		case t := <-c.rcv_deadline_set:
			c.set_deadline(t)

		case cmd := <-c.snd_chan:
			c.snd_pkt(cmd)

		case cmd := <-c.close_chan:
			c.close_cmd = cmd
			c.snd_pkt(cmd_channel_snd{pkt: &pkt_t{hdr: pkt_hdr_t{End: true}}})

		case pkt := <-c.rcv_chan_i:
			c.rcv_pkt(pkt)

		case rcv_chan_o <- rcv_cmd:
			c.rcv_pkt_buf = nil

		}

		if c.state.test(channel_snd_end|channel_rcv_end, 0) {
			break
		}
	}
}

func (c *rawChannel) run_terminating_rcv_end_loop() {
	for c.state.test(channel_open, 0) {
		var (
			rcv_chan_o        chan cmd_channel_rcv
			rcv_deadline_chan <-chan time.Time
			rcv_cmd           cmd_channel_rcv
		)

		if c.rcv_pkt_buf != nil || c.rcv_deadline_reached {
			rcv_chan_o = c.rcv_chan_o

			if c.rcv_deadline_reached {
				rcv_cmd.pkt = c.rcv_pkt_buf
				rcv_cmd.err = nil
			} else {
				rcv_cmd.pkt = nil
				rcv_cmd.err = ErrTimeout
			}
		}

		if c.rcv_deadline != nil {
			rcv_deadline_chan = c.rcv_deadline.C
		}

		select {

		case <-rcv_deadline_chan:
			c.rcv_deadline_reached = true

		case t := <-c.rcv_deadline_set:
			c.set_deadline(t)

		case cmd := <-c.snd_chan:
			cmd.reply <- ErrSendOnClosedChannel

		case <-c.rcv_chan_i:
			// drop pkt

		case rcv_chan_o <- rcv_cmd:
			c.rcv_pkt_buf = nil
			c.state.mod(0, channel_open)

		}
	}
}

func (c *rawChannel) setup() {

}

func (c *rawChannel) teardown() {
	c.line.unregister_channel(c)

	// flush the channels
	for cmd := range c.snd_chan {
		cmd.reply <- ErrSendOnClosedChannel
	}
	for _ = range c.rcv_chan_i {
	}
	for _ = range c.rcv_deadline_set {
	}

	// handle close
	if c.close_cmd.reply != nil {
		c.close_cmd.reply <- c.rcv_err
	}
	for cmd := range c.close_chan {
		cmd.reply <- c.rcv_err
	}

}

func (c *rawChannel) run_terminating_snd_end_loop() {
	// shutdown imediatly
	c.state.mod(0, channel_open)
}

func (c *rawChannel) set_deadline(t time.Time) {
	c.rcv_deadline_reached = false
	if t.IsZero() {
		c.rcv_deadline = nil
	} else {
		c.rcv_deadline = time.NewTimer(t.Sub(time.Now()))
	}
}

func (c *rawChannel) snd_pkt(cmd cmd_channel_snd) {
	cmd.pkt.hdr.C = c.id

	err := c.line.Snd(cmd.pkt)
	if err != nil {
		if cmd.reply != nil {
			cmd.reply <- err
		}
	}

	if cmd.pkt.hdr.Err != "" {
		c.state.mod(channel_snd_end, 0)
	}

	if cmd.pkt.hdr.End {
		c.state.mod(channel_snd_end, 0)
	}

	if cmd.reply != nil {
		cmd.reply <- nil
	}
}

func (c *rawChannel) rcv_pkt(pkt *pkt_t) {
	c.rcv_pkt_buf = pkt

	if pkt.hdr.Err != "" {
		pkt.hdr.End = true
		c.rcv_err = errors.New(pkt.hdr.Err)
	}

	if pkt.hdr.End {
		c.state.mod(channel_rcv_end, 0)
	}
}
