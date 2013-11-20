package telehash

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/fd/go-util/log"
	"io"
)

type Switch struct {
	main  *main_controller
	net   *net_controller
	peers *peer_controller
	addr  string
	key   *rsa.PrivateKey
	mux   *SwitchMux
	log   log.Logger
}

type Channel struct {
	c *channel_t
}

func NewSwitch(addr string, key *rsa.PrivateKey, handler Handler) (*Switch, error) {
	mux := NewSwitchMux()

	mux.HandleFallback(handler)

	hn, err := HashnameFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	s := &Switch{
		addr: addr,
		key:  key,
		mux:  mux,
		log:  Log.Sub(log.DEFAULT, "switch["+addr+":"+hn.Short()+"]"),
	}

	return s, nil
}

func (s *Switch) Start() error {

	main, err := main_controller_open(s)
	if err != nil {
		return err
	}
	s.main = main

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

	return nil
}

func (s *Switch) Stop() error {
	s.net.close()
	s.main.close()
	return nil
}

func (s *Switch) LocalHashname() Hashname {
	return s.peers.get_local_hashname()
}

func (s *Switch) Seed(addr string, key *rsa.PublicKey) (Hashname, error) {
	paddr, err := make_addr(ZeroHashname, ZeroHashname, addr, key)
	if err != nil {
		return ZeroHashname, err
	}

	peer, discovered := s.peers.add_peer(paddr)

	if discovered {
		peer.send_seek_cmd(s.LocalHashname())
	}

	return peer.addr.hashname, nil
}

func (s *Switch) Seek(hashname Hashname, n int) []Hashname {
	peers := s.peers.seek(hashname, n)
	hashnames := make([]Hashname, len(peers))

	for i, peer := range peers {
		hashnames[i] = peer.addr.hashname
	}

	return hashnames
}

func (s *Switch) Open(hashname Hashname, typ string) (*Channel, error) {
	peer := s.peers.get_peer(hashname)
	if peer == nil {
		return nil, ErrUnknownPeer
	}

	channel, err := peer.open_channel(&pkt_t{
		hdr: pkt_hdr_t{Type: typ},
	}, false)

	if err != nil {
		return nil, err
	}

	return &Channel{channel}, nil
}

func (c *Channel) Close() error {
	return c.c.snd_pkt(&pkt_t{hdr: pkt_hdr_t{End: true}})
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

	return len(body), c.c.snd_pkt(pkt)
}

func (c *Channel) Receive(hdr interface{}, body []byte) (n int, err error) {
	pkt, err := c.c.pop_rcv_pkt()
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
