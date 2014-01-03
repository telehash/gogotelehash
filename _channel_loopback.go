package telehash

import (
	"errors"
	"github.com/fd/go-util/log"
	"io"
	"runtime/debug"
	"time"
)

type channel_loopback_t struct {
	sw                 *Switch
	id                 string
	typ                string
	other_side         *channel_loopback_t
	c_set_rcv_deadline chan time.Time
	c_snd_pkt          chan cmd_push_rcv_pkt
	c_pop_rcv_pkt      chan chan cmd_pop_rcv_pkt_res
	c_push_rcv_pkt     chan cmd_push_rcv_pkt
	err                error
	log                log.Logger
}

type cmd_push_rcv_pkt struct {
	pkt   *pkt_t
	err_c chan error
}

type cmd_pop_rcv_pkt_res struct {
	pkt *pkt_t
	err error
}

func (c *channel_loopback_t) To() Hashname {
	return c.sw.hashname
}

func (c *channel_loopback_t) Id() string {
	return c.id
}

func (c *channel_loopback_t) Type() string {
	return c.typ
}

func (c *channel_loopback_t) Reliablility() Reliablility {
	return ReliableChannel
}

func (c *channel_loopback_t) Close() error {
	return c.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true}})
}

func (c *channel_loopback_t) Send(hdr interface{}, body []byte) (int, error) {
	return exported_snd_pkt(c, hdr, body)
}

func (c *channel_loopback_t) Receive(hdr interface{}, body []byte) (n int, err error) {
	return exported_rcv_pkt(c, hdr, body)
}

func (c *channel_loopback_t) Write(b []byte) (n int, err error) {
	return c.Send(nil, b)
}

func (c *channel_loopback_t) Read(b []byte) (n int, err error) {
	return c.Receive(nil, b)
}

func (c *channel_loopback_t) set_rcv_deadline(at time.Time) {
	c.c_set_rcv_deadline <- at
}

func (c *channel_loopback_t) pop_rcv_pkt() (*pkt_t, error) {
	reply_c := make(chan cmd_pop_rcv_pkt_res)
	c.c_pop_rcv_pkt <- reply_c
	reply := <-reply_c
	return reply.pkt, reply.err
}

func (c *channel_loopback_t) push_rcv_pkt(pkt *pkt_t) error {
	panic("this is a loopback channel")
}

func (c *channel_loopback_t) snd_pkt(pkt *pkt_t) error {
	err_c := make(chan error)
	c.c_snd_pkt <- cmd_push_rcv_pkt{pkt, err_c}
	return <-err_c
}

func (c *channel_loopback_t) tick(now time.Time) (ack *pkt_t, miss []*pkt_t) {
	panic("this is a loopback channel")
}

func (c *channel_loopback_t) mark_as_broken() {
	panic("this is a loopback channel")
}

func (c *channel_loopback_t) line_state_changed() {
	panic("this is a loopback channel")
}

func (c *channel_loopback_t) is_closed() bool {

}

func (c *channel_loopback_t) run_user_handler() {
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

	c.sw.mux.ServeTelehash(c)
}

func (c *channel_loopback_t) run_loop() {
	var (
		rcv_deadline_t       *time.Timer
		rcv_deadline_c       <-chan time.Time
		rcv_deadline_reached bool
		pop_rcv_pkt_c        chan chan cmd_pop_rcv_pkt_res
		push_rcv_pkt_c       chan cmd_push_rcv_pkt
		rcv_c                chan cmd_pop_rcv_pkt_res
		snd_pkt_c            chan cmd_push_rcv_pkt
		push_snd_pkt_c       chan cmd_push_rcv_pkt
		snd_cmd              cmd_push_rcv_pkt
	)

	defer func() {

		if rcv_deadline_t != nil {
			rcv_deadline_t.Stop()
		}

		if rcv_c != nil {
			rcv_c <- cmd_pop_rcv_pkt_res{err: c.err}
		}

		if snd_cmd.err_c == nil {

		}

		close(c.c_pop_rcv_pkt)
		close(c.c_push_rcv_pkt)
		close(c.c_set_rcv_deadline)

	}()

	for {

		if rcv_deadline_t != nil {
			rcv_deadline_c = rcv_deadline_t.C
		}

		if snd_cmd.err_c == nil {
			// enable snd
			// block push
			snd_pkt_c = c.c_snd_pkt
			push_snd_pkt_c = nil
		} else {
			// block snd
			// enable push
			snd_pkt_c = nil
			push_snd_pkt_c = c.other_side.c_push_rcv_pkt
		}

		if rcv_c == nil {
			// enable pop pkt
			// block push pkt
			pop_rcv_pkt_c = c.c_pop_rcv_pkt
			push_rcv_pkt_c = nil
		} else {
			// enable push pkt
			// block pop pkt
			push_rcv_pkt_c = c.c_push_rcv_pkt
			pop_rcv_pkt_c = nil
		}

		select {

		case push_snd_pkt_c <- snd_cmd:
			snd_cmd = cmd_push_rcv_pkt{}

		case cmd := <-snd_pkt_c:
			snd_cmd = cmd

		case cmd := <-push_rcv_pkt_c:
			rcv_c <- cmd_pop_rcv_pkt_res{pkt: cmd.pkt}
			rcv_c = nil
			cmd.err_c <- nil
			if cmd.pkt.hdr.End {
				if cmd.pkt.hdr.Err != "" {
					c.err = errors.New(cmd.pkt.hdr.Err)
				} else {
					c.err = io.EOF
				}
				return
			}

		case c := <-pop_rcv_pkt_c:
			if rcv_deadline_reached {
				c <- cmd_pop_rcv_pkt_res{err: ErrTimeout}
			} else {
				rcv_c = c
			}

		case at := <-c.c_set_rcv_deadline:
			now := time.Now()
			rcv_deadline_reached = now.After(at)
			if rcv_deadline_reached {
				rcv_deadline_t = nil
				if rcv_c != nil {
					rcv_c <- cmd_pop_rcv_pkt_res{pkt: cmd.pkt}
					rcv_c = nil
				}
			} else if at.IsZero() {
				if rcv_deadline_t != nil {
					rcv_deadline_t.Stop()
					rcv_deadline_t = nil
				}
			} else {
				d := now.Sub(at)
				if rcv_deadline_t == nil {
					rcv_deadline_t = time.NewTimer(d)
				} else {
					rcv_deadline_t.Reset(d)
				}
			}

		case <-rcv_deadline_c:
			rcv_deadline_t = nil
			rcv_deadline_reached = true
			if rcv_c != nil {
				rcv_c <- cmd_pop_rcv_pkt_res{pkt: cmd.pkt}
				rcv_c = nil
			}

		}
	}
}
