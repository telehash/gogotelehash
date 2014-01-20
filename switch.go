package telehash

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/fd/go-util/log"
	"github.com/rcrowley/go-metrics"
	"github.com/telehash/gogotelehash/net"
	"sync"
	"time"
)

type Switch struct {
	DenyRelay  bool
	Key        *rsa.PrivateKey
	Handler    Handler
	Transports []net.Transport

	reactor       reactor_t
	peers         peer_table
	transports    map[string]net.Transport
	lines         map[Hashname]*line_t
	active_lines  map[string]*line_t
	peer_handler  peer_handler
	seek_handler  seek_handler
	path_handler  path_handler
	relay_handler relay_handler
	stats_timer   *time.Timer
	clean_timer   *time.Timer
	mtx           sync.Mutex
	hashname      Hashname
	mux           *SwitchMux
	log           log.Logger
	terminating   bool
	running       bool

	met_open_lines    metrics.Gauge
	met_running_lines metrics.Gauge
	met_channels      metrics.Counter
	met               metrics.Registry
}

func (s *Switch) Start() error {
	var (
		err error
	)

	s.mtx.Lock()
	defer s.mtx.Unlock()

	if s.running {
		return ErrSwitchAlreadyRunning
	}

	// make random key
	if s.Key == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		s.Key = key
	}

	// make local hashname
	{
		hn, err := HashnameFromPublicKey(&s.Key.PublicKey)
		if err != nil {
			return err
		}
		s.hashname = hn
	}

	s.met = metrics.NewRegistry()
	s.met_channels = metrics.NewRegisteredCounter("channels.num", s.met)
	s.met_open_lines = metrics.NewRegisteredGauge("lines.num.open", s.met)
	s.met_running_lines = metrics.NewRegisteredGauge("lines.num.running", s.met)

	s.lines = make(map[Hashname]*line_t)
	s.active_lines = make(map[string]*line_t)
	s.transports = make(map[string]net.Transport, len(s.Transports))
	s.log = Log.Sub(log.DEFAULT, "switch["+s.hashname.Short()+"]")
	s.mux = NewSwitchMux()
	s.mux.HandleFallback(s.Handler)

	s.reactor.sw = s
	s.peers.Init(s.hashname)
	s.peer_handler.init(s)
	s.seek_handler.init(s)
	s.path_handler.init(s)
	s.relay_handler.init(s)

	for _, t := range s.Transports {
		if _, p := s.transports[t.Network()]; p {
			err = fmt.Errorf("transport %q is already registerd", t.Network())
			break
		}

		s.transports[t.Network()] = t

		err = t.Open()
		if err != nil {
			break
		}

		go s.listen(t)
	}
	if err != nil {
		for _, t := range s.Transports {
			t.Close()
		}
		return err
	}

	s.running = true
	s.reactor.Run()
	s.stats_timer = s.reactor.CastAfter(5*time.Second, &cmd_stats_log{})
	s.clean_timer = s.reactor.CastAfter(2*time.Second, &cmd_clean{})

	return nil
}

func (s *Switch) listen(t net.Transport) {
	var (
		buf     = make([]byte, 1500)
		network = t.Network()
	)

	for {
		n, addr, err := t.ReadFrom(buf)
		if err == net.ErrTransportClosed {
			return
		}
		if err != nil {
			// drop
			continue
		}

		pkt, err := parse_pkt(buf[:n], nil, &net_path{Network: network, Address: addr})
		if err != nil {
			// drop
			continue
		}

		err = s.rcv_pkt(pkt)
		if err != nil {
			// drop
			continue
		}
	}
}

func (s *Switch) Stop() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.reactor.Cast(&cmd_shutdown{})
	s.reactor.StopAndWait()

	for _, t := range s.transports {
		t.Close()
	}

	stop_timer(s.stats_timer)
	stop_timer(s.clean_timer)
	s.running = false
	return nil
}

func (s *Switch) LocalHashname() Hashname {
	return s.hashname
}

func (s *Switch) Seed(net string, addr net.Addr, key *rsa.PublicKey) (Hashname, error) {
	hashname, err := HashnameFromPublicKey(key)
	if err != nil {
		return ZeroHashname, err
	}

	peer, newpeer := s.add_peer(hashname)
	peer.SetPublicKey(key)
	peer.add_net_path(&net_path{Network: net, Address: addr})
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
	cmd := cmd_channel_open{options, nil}
	err := s.reactor.Call(&cmd)
	return cmd.channel, err
}

func (s *Switch) get_peer(hashname Hashname) *Peer {
	cmd := cmd_peer_get{hashname, nil}
	s.reactor.Call(&cmd)
	return cmd.peer
}

func (s *Switch) get_closest_peers(hashname Hashname, n int) []*Peer {
	cmd := cmd_peer_get_closest{hashname, n, nil}
	s.reactor.Call(&cmd)
	return cmd.peers
}

func (s *Switch) add_peer(hashname Hashname) (*Peer, bool) {
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

func (s *Switch) snd_pkt(pkt *pkt_t) error {
	if pkt.netpath == nil {
		return ErrInvalidNetwork
	}

	if pkt.netpath.Network == "relay" {
		return s.relay_handler.snd_pkt(s, pkt)
	}

	transport := s.transports[pkt.netpath.Network]
	if transport == nil {
		return ErrInvalidNetwork
	}

	data, err := pkt.format_pkt()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(data, pkt.netpath.Address)
	if err != nil {
		return err
	}

	return nil
}

func (s *Switch) send_nat_breaker(peer *Peer) {
	if peer == nil {
		return
	}

	for _, np := range peer.net_paths() {
		if np.Address.NeedNatHolePunching() {
			s.snd_pkt(&pkt_t{netpath: np})
		}
	}
}

func (s *Switch) get_network_paths() net_paths {
	var (
		paths net_paths
	)

	for n, t := range s.transports {
		for _, a := range t.LocalAddresses() {
			paths = append(paths, &net_path{Network: n, Address: a})
		}
	}

	return paths
}
