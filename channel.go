package telehash

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

type Channel interface {
	To() Hashname
	Id() string
	Type() string
	Reliablility() Reliablility

	Send(hdr interface{}, body []byte) (int, error)
	Receive(hdr interface{}, body []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Read(b []byte) (n int, err error)
	Close() error

	set_rcv_deadline(at time.Time)
	pop_rcv_pkt() (*pkt_t, error)
	push_rcv_pkt(pkt *pkt_t) error
	snd_pkt(pkt *pkt_t) error
	is_closed() bool

	// problems
	tick(now time.Time) (ack *pkt_t, miss []*pkt_t)
	mark_as_broken()
	line_state_changed()
	run_user_handler()
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

func make_channel(sw *Switch, line *line_t, initiator bool, options ChannelOptions) (Channel, error) {
	if options.Id == "" {
		bin_id, err := make_rand(16)
		if err != nil {
			return nil, err
		}

		options.Id = hex.EncodeToString(bin_id)
	}

	return make_channel_reliable(sw, line, initiator, options)
}

func exported_snd_pkt(c Channel, hdr interface{}, body []byte) (int, error) {
	pkt := &pkt_t{}

	if hdr != nil {
		custom, err := json.Marshal(hdr)
		if err != nil {
			return 0, err
		}
		pkt.hdr.Custom = json.RawMessage(custom)
	}

	pkt.body = body

	return len(body), c.snd_pkt(pkt)
}

func exported_rcv_pkt(c Channel, hdr interface{}, body []byte) (n int, err error) {
	pkt, err := c.pop_rcv_pkt()
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
