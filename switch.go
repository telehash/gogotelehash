package telehash

import (
	"crypto/rsa"
	"encoding/json"
)

type Switch struct {
	conn    *channel_handler
	addr    string
	key     *rsa.PrivateKey
	handler Handler
}

type Handler interface {
	ServeTelehash(ch *Channel)
}

type HandlerFunc func(*Channel)

type Channel struct {
	c *channel_t
}

func NewSwitch(addr string, key *rsa.PrivateKey, handler Handler) (*Switch, error) {
	s := &Switch{
		addr:    addr,
		key:     key,
		handler: handler,
	}

	return s, nil
}

func (s *Switch) Start() error {
	conn, err := channel_handler_open(s.addr, s.key, channel_handler_func(s.handle_telehash))
	if err != nil {
		return err
	}

	s.conn = conn
	return nil
}

func (s *Switch) Stop() error {
	s.conn.close()
	return nil
}

func (s *Switch) RegisterPeer(addr string, key *rsa.PublicKey) (string, error) {
	return s.conn.add_peer(addr, key)
}

func (s *Switch) Open(hashname, typ string) (*Channel, error) {
	channel, err := s.conn.open_channel(hashname, &pkt_t{
		hdr: pkt_hdr_t{Type: typ},
	})

	if err != nil {
		return nil, err
	}

	return &Channel{channel}, nil
}

func (s *Switch) handle_telehash(ch *channel_t) {
	if s.handler != nil {
		s.handler.ServeTelehash(&Channel{ch})
	}
}

func (c *Channel) Close() error {
	return c.c.close()
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

	return c.c.send(pkt)
}

func (c *Channel) Receive(hdr interface{}) (body []byte, err error) {
	pkt, err := c.c.receive()
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

func (f HandlerFunc) ServeTelehash(ch *Channel) {
	f(ch)
}
