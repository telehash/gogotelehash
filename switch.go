package telehash

import (
	"crypto/rsa"
	"github.com/fd/go-util/log"
	"github.com/telehash/gogotelehash/net"
	"time"
)

type Switch struct {
	AllowRelay    bool
	reactor       reactor_t
	net           *net_controller
	peers         peer_table
	lines         map[Hashname]*line_t
	active_lines  map[string]*line_t
	peer_handler  peer_handler
	seek_handler  seek_handler
	path_handler  path_handler
	relay_handler relay_handler
	stats_timer   *time.Timer
	clean_timer   *time.Timer
	addr          string
	hashname      Hashname
	key           *rsa.PrivateKey
	mux           *SwitchMux
	log           log.Logger
	terminating   bool

	num_open_lines    int32
	num_running_lines int32
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
		addr:         addr,
		key:          key,
		hashname:     hn,
		mux:          mux,
		lines:        make(map[Hashname]*line_t),
		active_lines: make(map[string]*line_t),
		log:          Log.Sub(log.DEFAULT, "switch["+addr+":"+hn.Short()+"]"),

		AllowRelay: true,
	}

	s.reactor.sw = s
	s.peers.Init(s.hashname)
	s.peer_handler.init(s)
	s.seek_handler.init(s)
	s.path_handler.init(s)
	s.relay_handler.init(s)

	return s, nil
}

func (s *Switch) Start() error {
	s.reactor.Run()
	s.stats_timer = s.reactor.CastAfter(5*time.Second, &cmd_stats_log{})
	s.clean_timer = s.reactor.CastAfter(2*time.Second, &cmd_clean{})

	net, err := net_controller_open(s)
	if err != nil {
		return err
	}
	s.net = net

	return nil
}

func (s *Switch) Listen(net string, t net.Transport) error {
	var (
		buf = make([]byte, 1400)
	)

	for {
		n, addr, err := t.ReadFrom(buf)
		if err != nil {
			return err
		}

		pkt, err := parse_pkt(buf[:n], nil, &net_path{Network: net, Address: addr})
		if err != nil {
			return err
		}

		err = s.rcv_pkt(pkt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Switch) Stop() error {
	s.reactor.Cast(&cmd_shutdown{})
	s.net.close()
	s.reactor.StopAndWait()
	stop_timer(s.stats_timer)
	stop_timer(s.clean_timer)
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

	netpath, err := ParseIPnet_path(addr)
	if err != nil {
		return ZeroHashname, err
	}

	peer, newpeer := s.AddPeer(hashname)
	peer.SetPublicKey(key)
	peer.add_net_path(netpath)
	if newpeer {
		peer.set_active_paths(peer.net_paths())
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
	cmd := cmd_channel_open{options, nil, nil}
	s.reactor.Call(&cmd)
	return cmd.channel, cmd.err
}

func (s *Switch) GetPeer(hashname Hashname) *Peer {
	cmd := cmd_peer_get{hashname, nil}
	s.reactor.Call(&cmd)
	return cmd.peer
}

func (s *Switch) GetClosestPeers(hashname Hashname, n int) []*Peer {
	cmd := cmd_peer_get_closest{hashname, n, nil}
	s.reactor.Call(&cmd)
	return cmd.peers
}

func (s *Switch) AddPeer(hashname Hashname) (*Peer, bool) {
	cmd := cmd_peer_add{hashname, nil, false}
	s.reactor.Call(&cmd)
	return cmd.peer, cmd.discovered
}

func (s *Switch) get_line(to Hashname) *line_t {
	cmd := cmd_line_get{to, nil}
	s.reactor.Call(&cmd)
	return cmd.line
}

func (s *Switch) get_active_line(to Hashname) *line_t {
	line := s.get_line(to)
	if line != nil && line.state == line_opened {
		return line
	}
	return nil
}

func (s *Switch) rcv_pkt(pkt *pkt_t) error {
	cmd := cmd_rcv_pkt{pkt}
	s.reactor.Cast(&cmd)
	return nil
}
