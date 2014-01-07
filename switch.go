package telehash

import (
	"crypto/rsa"
	"github.com/fd/go-util/log"
)

type Switch struct {
	AllowRelay    bool
	reactor       reactor_t
	main          *main_controller
	net           *net_controller
	peer_handler  peer_handler
	seek_handler  seek_handler
	path_handler  path_handler
	relay_handler relay_handler
	addr          string
	hashname      Hashname
	key           *rsa.PrivateKey
	mux           *SwitchMux
	log           log.Logger
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

	s.reactor.sw = s
	s.peer_handler.init(s)
	s.seek_handler.init(s)
	s.path_handler.init(s)
	s.relay_handler.init(s)

	return s, nil
}

func (s *Switch) Start() error {
	s.reactor.Run()

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
	s.reactor.StopAndWait()
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

	peer, newpeer := s.main.AddPeer(hashname)
	peer.SetPublicKey(key)
	peer.AddNetPath(netpath)
	if newpeer {
		peer.set_active_paths(peer.NetPaths())
	}

	err = s.seek_handler.Seek(hashname, s.hashname)
	if err != nil {
		return hashname, err
	}

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

func (s *Switch) Open(options ChannelOptions) (*Channel, error) {
	return s.main.OpenChannel(options)
}
