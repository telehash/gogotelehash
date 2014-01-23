package telehash

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/fd/go-util/log"
	"io"
	"runtime/debug"
	"time"
)

type Channel struct {
	initiator            bool
	options              ChannelOptions
	imp                  channel_imp
	line                 *line_t
	sw                   *Switch
	broken               bool
	broken_timer         *time.Timer
	snd_backlog          backlog_t
	snd_end              bool
	rcv_backlog          backlog_t
	rcv_deadline         *time.Timer
	rcv_deadline_reached bool
	rcv_end              bool
	rcv_err              string
	read_end             bool
	log                  log.Logger
}

type channel_imp interface {
	can_pop_rcv_pkt() bool
	can_snd_pkt() bool
	pop_rcv_pkt() (*pkt_t, error)
	push_rcv_pkt(pkt *pkt_t) error
	will_send_packet(pkt *pkt_t) error
	did_send_packet(pkt *pkt_t)
	is_closed() bool
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

func make_channel(sw *Switch, line *line_t, initiator bool, options ChannelOptions) (*Channel, error) {
	var (
		imp channel_imp
		err error
	)

	if options.Id == "" {
		bin_id, err := make_rand(16)
		if err != nil {
			return nil, err
		}

		options.Id = hex.EncodeToString(bin_id)
	}

	channel := &Channel{
		line:      line,
		sw:        sw,
		options:   options,
		initiator: initiator,
		log:       line.log.Sub(log_level_for("CHANNEL", log.DEFAULT), "channel["+options.Id[:8]+"]"),
	}

	switch options.Reliablility {
	case ReliableChannel:
		imp, err = make_channel_reliable(line, channel)
	case UnreliableChannel:
		imp, err = make_channel_unreliable(line, channel)
	case StatelessChannel:
		imp, err = make_channel_stateless(line, channel)
	default:
		panic("unknown channel type")
	}
	if err != nil {
		return nil, err
	}
	channel.imp = imp

	return channel, nil
}

func (c *Channel) To() Hashname {
	return c.options.To
}

func (c *Channel) Peer() *Peer {
	return c.line.peer
}

func (c *Channel) Id() string {
	return c.options.Id
}

func (c *Channel) Type() string {
	return c.options.Type
}

func (c *Channel) Reliablility() Reliablility {
	return c.options.Reliablility
}

func (c *Channel) SendPacket(hdr interface{}, body []byte) (int, error) {
	pkt := packet_pool_acquire()

	if hdr != nil {
		pkt.hdr_value = hdr

		if special, ok := hdr.(ChannelErrHeader); ok {
			pkt.priv_hdr.Err = special.Err()
		}

		if special, ok := hdr.(ChannelEndHeader); ok {
			pkt.priv_hdr.End = special.End()
		}

		if special, ok := hdr.(channelNetPathHeader); ok {
			pkt.netpath = special.get_net_path()
		}
	}

	if body != nil {
		pkt.body = body
	}

	err := c.send_packet(pkt)
	if err != nil {
		return 0, err
	}

	return len(body), nil
}

func (c *Channel) ReceivePacket(hdr interface{}, body []byte) (int, error) {
	var (
		n int
	)

	pkt, err := c.receive_packet()
	defer packet_pool_release(pkt)
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

	if hdr != nil {
		err = json.Unmarshal(pkt.hdr, hdr)
		if err != nil {
			return 0, err
		}

		if special, ok := hdr.(channelNetPathHeader); ok {
			special.set_net_path(pkt.netpath)
		}
	}

	return n, nil
}

func (c *Channel) Send(hdr interface{}, body []byte) (int, error) {
	if hdr != nil {
		hdr = &pkt_hdr_app{Custom: hdr}
	}

	return c.SendPacket(hdr, body)
}

func (c *Channel) Receive(hdr interface{}, body []byte) (n int, err error) {
	if hdr != nil {
		hdr = &pkt_hdr_app{Custom: hdr}
	}

	return c.ReceivePacket(hdr, body)
}

func (c *Channel) Write(b []byte) (n int, err error) {
	return c.Send(nil, b)
}

func (c *Channel) Read(b []byte) (n int, err error) {
	return c.Receive(nil, b)
}

func (c *Channel) Close() error {
	_, err := c.SendPacket(&channel_basic_end_header{}, nil)
	return err
}

func (c *Channel) Fatal(err error) error {
	_, err = c.SendPacket(&channel_basic_err_header{err.Error()}, nil)
	return err
}

func (c *Channel) send_packet(p *pkt_t) error {
	if c == nil {
		return ErrChannelBroken
	}
	cmd := cmd_snd_pkt{c, c.line, p, false}
	return c.sw.reactor.Call(&cmd)
}

func (c *Channel) receive_packet() (*pkt_t, error) {
	if c == nil {
		return nil, ErrChannelBroken
	}
	cmd := cmd_get_rcv_pkt{c, nil, nil}
	err := c.sw.reactor.Call(&cmd)
	return cmd.pkt, err
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

func (c *Channel) can_pop_rcv_pkt() bool {
	if c.broken || c.snd_end || c.read_end || c.rcv_deadline_reached {
		return true
	}

	return c.imp.can_pop_rcv_pkt()
}

func (c *Channel) can_snd_pkt() bool {
	if c.rcv_end || c.snd_end || c.broken {
		return true
	}

	return c.imp.can_snd_pkt()
}

func (c *Channel) pop_rcv_pkt() (*pkt_t, error) {
	defer c.reschedule()

	if c.broken {
		return nil, ErrChannelBroken
	}

	if c.snd_end {
		return nil, ErrReceiveOnClosedChannel
	}

	if c.rcv_deadline_reached {
		return nil, ErrTimeout
	}

	if c.read_end {
		return nil, io.EOF
	}

	pkt, err := c.imp.pop_rcv_pkt()
	if err != nil {
		return pkt, err
	}

	if pkt.priv_hdr.End {
		c.read_end = true
	}

	return pkt, nil
}

func (c *Channel) push_rcv_pkt(pkt *pkt_t) error {
	err := c.imp.push_rcv_pkt(pkt)

	// mark the end pkt
	if pkt.priv_hdr.End {
		c.rcv_end = true
	}
	if pkt.priv_hdr.Err != "" {
		c.rcv_end = true
		c.rcv_err = pkt.priv_hdr.Err
	}

	// c.log.Debugf("rcv pkt: hdr=%+v", pkt.hdr)

	if err == nil {
		if c.broken_timer == nil {
			c.broken_timer = c.sw.reactor.CastAfter(60*time.Second, &cmd_channel_break{c})
		} else {
			c.broken_timer.Reset(60 * time.Second)
		}
	}

	c.reschedule()
	return err
}

func (c *Channel) will_send_packet(pkt *pkt_t) error {
	if c.broken {
		return ErrChannelBroken
	}

	if c.snd_end {
		return ErrSendOnClosedChannel
	}

	if c.rcv_end {
		return ErrSendOnClosedChannel
	}

	pkt.priv_hdr.C = c.options.Id

	return c.imp.will_send_packet(pkt)
}

func (c *Channel) did_send_packet(pkt *pkt_t) {
	if pkt.priv_hdr.End {
		c.snd_end = true
	}

	c.imp.did_send_packet(pkt)
	c.reschedule()
}

func (c *Channel) is_closed() bool {
	if len(c.rcv_backlog) > 0 || len(c.snd_backlog) > 0 {
		return false
	}

	if c.broken {
		return true
	}

	return c.imp.is_closed()
}

func (c *Channel) mark_as_broken() {
	c.broken = true
}

func (c *Channel) reschedule() {
	if len(c.rcv_backlog) > 0 && c.can_pop_rcv_pkt() {
		c.rcv_backlog.RescheduleOne(&c.sw.reactor)
	}

	if len(c.snd_backlog) > 0 && c.can_snd_pkt() {
		c.snd_backlog.RescheduleOne(&c.sw.reactor)
	}
}

func (c *Channel) reschedule_all() {
	if len(c.rcv_backlog) > 0 && c.can_pop_rcv_pkt() {
		c.rcv_backlog.RescheduleAll(&c.sw.reactor)
	}

	if len(c.snd_backlog) > 0 && c.can_snd_pkt() {
		c.snd_backlog.RescheduleAll(&c.sw.reactor)
	}
}

func (c *Channel) SetReceiveDeadline(t time.Time) {
	cmd := cmd_channel_set_rcv_deadline{c, t}
	c.sw.reactor.Call(&cmd)
}

type cmd_channel_break struct {
	channel *Channel
}

func (cmd *cmd_channel_break) Exec(sw *Switch) error {
	cmd.channel.broken = true
	cmd.channel.reschedule_all()
	return nil
}
