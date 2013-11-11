package telehash

import (
	"crypto/rsa"
	"encoding/json"
	"io"
)

type Switch struct {
	net      *net_controller
	channels *channel_controller
	peers    *peer_controller
	lines    *line_controller
	addr     string
	key      *rsa.PrivateKey
	mux      *SwitchMux
}

type Channel struct {
	c *channel_t
}

func NewSwitch(addr string, key *rsa.PrivateKey, handler Handler) (*Switch, error) {
	mux := NewSwitchMux()

	mux.HandleFallback(handler)

	s := &Switch{
		addr: addr,
		key:  key,
		mux:  mux,
	}

	return s, nil
}

func (s *Switch) Start() error {

	net, err := net_controller_open(s)
	if err != nil {
		return err
	}
	s.net = net

	peers, err := peer_controller_open(s)
	if err != nil {
		return err
	}
	s.peers = peers

	lines, err := line_controller_open(s)
	if err != nil {
		return err
	}
	s.lines = lines

	channels, err := channel_controller_open(s)
	if err != nil {
		return err
	}
	s.channels = channels

	return nil
}

func (s *Switch) Stop() error {
	s.channels.close()
	s.net.close()
	return nil
}

func (s *Switch) LocalHashname() Hashname {
	return s.peers.get_local_hashname()
}

func (s *Switch) Seed(addr string, key *rsa.PublicKey) (Hashname, error) {
	hashname, err := s.peers.add_peer(ZeroHashname, addr, key, ZeroHashname)
	if err != nil {
		return ZeroHashname, err
	}

	s.Seek(hashname, 15)
	return hashname, nil
}

func (s *Switch) Seek(hashname Hashname, n int) []Hashname {
	peers := s.peers.seek(hashname, n)
	hashnames := make([]Hashname, len(peers))

	for i, peer := range peers {
		hashnames[i] = peer.hashname
	}

	return hashnames
}

func (s *Switch) Open(hashname Hashname, typ string) (*Channel, error) {
	channel, err := s.channels.open_channel(hashname, &pkt_t{
		hdr: pkt_hdr_t{Type: typ},
	})

	if err != nil {
		return nil, err
	}

	return &Channel{channel}, nil
}

func (c *Channel) Close() error {
	return c.c.close()
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

	return len(body), c.c.send(pkt)
}

func (c *Channel) Receive(hdr interface{}, body []byte) (n int, err error) {
	pkt, err := c.c.receive()
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
