package telehash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime/debug"
	"time"
)

type Channel struct {
	imp         channel_i
	line        *line_t
	sw          *Switch
	snd_backlog backlog_t
}

type channel_i interface {
	To() Hashname
	Id() string
	Type() string
	Reliablility() Reliablility

	set_rcv_deadline(at time.Time)
	pop_rcv_pkt() (*pkt_t, error)
	push_rcv_pkt(pkt *pkt_t) error
	will_send_packet(pkt *pkt_t) (bool, error)
	did_send_packet(pkt *pkt_t)
	is_closed() bool

	// problems
	tick(now time.Time) (ack *pkt_t, miss []*pkt_t)
	mark_as_broken()
	line_state_changed()
}

type ChannelOptions struct {
	To           Hashname
	Type         string
	Id           string
	Reliablility Reliablility
}

type Reliablility uint8

const (
	ReliableChannel Reliablility = iota
	UnreliableChannel
	StatelessChannel
)

func make_channel(sw *Switch, line *line_t, initiator bool, options ChannelOptions) (channel_i, error) {
	if options.Id == "" {
		bin_id, err := make_rand(16)
		if err != nil {
			return nil, err
		}

		options.Id = hex.EncodeToString(bin_id)
	}

	return make_channel_reliable(sw, line, initiator, options)
}

func (c *Channel) To() Hashname {
	return c.imp.To()
}

func (c *Channel) Id() string {
	return c.imp.Id()
}

func (c *Channel) Type() string {
	return c.imp.Type()
}

func (c *Channel) Reliablility() Reliablility {
	return c.imp.Reliablility()
}

func (c *Channel) Send(hdr interface{}, body []byte) (int, error) {
	pkt := &pkt_t{}

	if hdr != nil {
		custom, err := json.Marshal(hdr)
		if err != nil {
			return 0, err
		}
		pkt.hdr.Custom = json.RawMessage(custom)
	}

	pkt.body = body

	err := c.send_packet(pkt)
	if err != nil {
		return 0, err
	}

	return len(body), nil
}

func (c *Channel) Receive(hdr interface{}, body []byte) (n int, err error) {
	pkt, err := c.imp.pop_rcv_pkt()
	if err != nil {
		return 0, err
	}

	if body != nil {
		if len(body) < len(pkt.body) {
			return 0, io.ErrShortBuffer
		}
		copy(body, pkt.body)
		n = len(pkt.body)
	}

	if len(pkt.hdr.Custom) > 0 {
		err = json.Unmarshal([]byte(pkt.hdr.Custom), hdr)
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (c *Channel) Write(b []byte) (n int, err error) {
	return c.Send(nil, b)
}

func (c *Channel) Read(b []byte) (n int, err error) {
	return c.Receive(nil, b)
}

func (c *Channel) Close() error {
	return c.send_packet(&pkt_t{hdr: pkt_hdr_t{End: true}})
}

func (c *Channel) Fatal(err error) error {
	return c.send_packet(&pkt_t{hdr: pkt_hdr_t{End: true, Err: err.Error()}})
}

func (c *Channel) send_packet(p *pkt_t) error {
	cmd := cmd_snd_pkt{c, c.line, p, nil}
	c.sw.reactor.Call(&cmd)
	return cmd.err
}

func (c *Channel) run_user_handler() {
	defer func() {
		c.log.Debug("handler returned: closing channel")

		r := recover()
		if r != nil {
			c.log.Errorf("panic: %s\n%s", r, debug.Stack())
			c.Fatal(errors.New("internal server error"))
		} else {
			c.Close()
		}
	}()

	c.sw.mux.ServeTelehash(c)
}
