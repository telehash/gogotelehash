package telehash

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/fd/go-util/log"
	"io"
)

type Switch struct {
	AllowRelay    bool
	main          *main_controller
	net           *net_controller
	peer_handler  peer_handler
	seek_handler  seek_handler
	ping_handler  ping_handler
	relay_handler relay_handler
	addr          string
	hashname      Hashname
	key           *rsa.PrivateKey
	mux           *SwitchMux
	log           log.Logger
}

type Channel struct {
	c *channel_t
}

func NewSwitch(addr string, key *rsa.PrivateKey, handler Handler) (*Switch, error) {
	mux := NewSwitchMux()

	if handler != nil {
		mux.HandleFallback(handler)
	}

	hn, err := HashnameFromPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	s := &Switch{
		addr:     addr,
		key:      key,
		hashname: hn,
		mux:      mux,
		log:      Log.Sub(log.DEFAULT, "switch["+addr+":"+hn.Short()+"]"),

		AllowRelay: true,
	}

	s.peer_handler.init(s)
	s.seek_handler.init(s)
	s.ping_handler.init(s)
	s.relay_handler.init(s)

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

	return nil
}

func (s *Switch) Stop() error {
	s.net.close()
	s.main.Close()
	return nil
}

func (s *Switch) LocalHashname() Hashname {
	return s.hashname
}

func (s *Switch) Seed(addr string, key *rsa.PublicKey) (Hashname, error) {
	hashname, err := HashnameFromPublicKey(key)
	if err != nil {
		return ZeroHashname, err
	}

	netpath, err := ParseIPNetPath(addr)
	if err != nil {
		return ZeroHashname, err
	}

	peer, _ := s.main.AddPeer(hashname)
	peer.SetPublicKey(key)
	peer.AddNetPath(netpath)

	s.main.GetLine(peer.Hashname())

	s.seek_handler.RecusiveSeek(s.hashname, 10)

	return hashname, nil
}

func (s *Switch) Seek(hashname Hashname, n int) []Hashname {
	peers := s.seek_handler.RecusiveSeek(hashname, n)
	hashnames := make([]Hashname, len(peers))

	for i, peer := range peers {
		hashnames[i] = peer.Hashname()
	}

	return hashnames
}

func (s *Switch) Open(hashname Hashname, typ string) (*Channel, error) {
	channel, err := s.main.OpenChannel(hashname, &pkt_t{
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
