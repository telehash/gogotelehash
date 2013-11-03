package telehash

import (
	"crypto/rsa"
	"errors"
	"net"
	"runtime"
	"time"
)

type pkt_udp_t struct {
	addr *net.UDPAddr
	data []byte
}

type command_i interface {
	exec(s *Switch) error
}

type Switch struct {
	identity   *rsa.PrivateKey
	hashname   string
	open_delta time.Duration // max open.at skew
	addr       string
	err        error

	conn        *net.UDPConn
	known_peers map[string]*peer_t  // hashname   -> peer
	lines       map[string]*line_t  // line_id    -> line (established lines)
	channels    map[string]*Channel // channel_id -> channel
	i_open      map[string]*line_t  // hashname   -> line (inbound open)
	o_open      map[string]*line_t  // hashname   -> line (outbound open)
	i_queue     chan pkt_udp_t      // inbound pkt queue
	o_queue     chan pkt_udp_t      // outbound pkt queue
	c_queue     chan command_i      // command queue
	a_queue     chan *Channel       // channel accept queue
	shutdown    chan bool
	closed      chan bool
}

func NewSwitch(addr string, key *rsa.PrivateKey) (*Switch, error) {
	hashname, err := hashname_from_RSA(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	s := &Switch{
		addr:       addr,
		identity:   key,
		open_delta: time.Second,
		hashname:   hashname,

		known_peers: make(map[string]*peer_t),
		lines:       make(map[string]*line_t),
		channels:    make(map[string]*Channel),
		i_open:      make(map[string]*line_t),
		o_open:      make(map[string]*line_t),
		i_queue:     make(chan pkt_udp_t),
		o_queue:     make(chan pkt_udp_t),
		c_queue:     make(chan command_i),
		a_queue:     make(chan *Channel),
		shutdown:    make(chan bool, 1),
		closed:      make(chan bool, 1),
	}

	return s, nil
}

func (s *Switch) RegisterPeer(addr string, pub *rsa.PublicKey) (string, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", err
	}

	hashname, err := hashname_from_RSA(pub)
	if err != nil {
		return "", err
	}

	s.c_queue <- &cmd_peer_register{
		peer: make_peer(s, hashname, udp_addr, pub),
	}

	return hashname, nil
}

func (s *Switch) open_line(hashname string) error {
	peer := s.lookup_peer(hashname)
	if peer == nil {
		return errors.New("unknown peer: " + hashname)
	}

	reply := make(chan error, 1)
	s.c_queue <- &cmd_open_o{peer, reply}
	return <-reply
}

func (s *Switch) Accept() *Channel {
	c := <-s.a_queue

	if c != nil {
		// start the control loop
		go c.control_loop()
	}

	return c
}

func (s *Switch) lookup_peer(hashname string) *peer_t {
	reply := make(chan *peer_t, 1)
	s.c_queue <- &cmd_peer_lookup{hashname, reply}
	return <-reply
}

func (s *Switch) Run() {
	udp_addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		s.err = err
		return
	}

	upd_conn, err := net.ListenUDP("udp", udp_addr)
	if err != nil {
		s.err = err
		return
	}

	s.conn = upd_conn

	go s.send_loop()
	go s.read_loop()
	go s.command_loop()

	for i := 0; i < runtime.NumCPU(); i++ {
		go s.dispatch_loop()
	}

	// wait for shutdown
	<-s.closed
	s.closed <- true
}

func (s *Switch) Close() error {
	close(s.a_queue)

	s.shutdown <- true
	<-s.closed
	s.closed <- true
	return s.err
}

func (s *Switch) read_loop() {
	defer func() { close(s.i_queue) }()

	for {
		select {
		case <-s.shutdown:
			s.shutdown <- true
			return
		default:
			// ignore
		}

		s.conn.SetReadDeadline(time.Now().Add(time.Second))

		buf := make([]byte, 1500)
		count, addr, err := s.conn.ReadFromUDP(buf)
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			continue
		}
		if err != nil {
			// Read failed; note the error and shutdown
			s.err = err
			return
		}

		// Log.Debugf("rcv pkt from %s", addr)
		s.i_queue <- pkt_udp_t{addr: addr, data: buf[:count]}
	}
}

func (s *Switch) send_loop() {
	defer func() { s.conn.Close() }()
	defer func() { s.closed <- true }()

	for pkt := range s.o_queue {
		_, err := s.conn.WriteToUDP(pkt.data, pkt.addr)
		if err != nil {
			// Read failed; note the error and shutdown
			s.err = err
			go s.Close()
			return
		}

		// Log.Debugf("snd pkt to %s", pkt.addr)
	}
}

func (s *Switch) command_loop() {
	defer func() { close(s.o_queue) }()

	for cmd := range s.c_queue {
		Log.Debugf("exec cmd %T %+v", cmd, cmd)
		err := cmd.exec(s)
		if err != nil {
			// Command failed; note the error and shutdown
			s.err = err
			go s.Close()
			return
		}
	}
}

func (s *Switch) dispatch_loop() {
	defer func() {
		defer func() { recover() }()
		close(s.c_queue)
	}()

	var (
		pkt *pkt_t
		err error
	)

	for udp_pkt := range s.i_queue {

		pkt, err = parse_pkt(udp_pkt.data, udp_pkt.addr)
		if err != nil {
			// failed to parse packet; drop it
			continue
		}

		// Log.Debugf("dsp %s pkt from %s", pkt.hdr.Type, pkt.addr)

		switch pkt.hdr.Type {
		case "open":
			s.c_queue <- &cmd_open_i{pkt}
		case "line":
			go s.handle_line(pkt)
		default:
			// failed to parse packet; drop it
		}

	}
}

func (s *Switch) handle_line(pkt *pkt_t) {
	line := s.lines[pkt.hdr.Line]
	if line == nil {
		Log.Debugf("dropped pkt: unknown line %s", pkt.hdr.Line)
		return
	}

	if pkt.addr.String() != line.peer.addr.String() {
		Log.Debugf("dropped pkt: wrong sender %s", pkt.addr)
		return
	}

	line.handle_pkt(pkt)
}

type cmd_peer_register struct {
	peer *peer_t
}

func (cmd *cmd_peer_register) exec(s *Switch) error {
	s.known_peers[cmd.peer.hashname] = cmd.peer
	return nil
}

type cmd_peer_lookup struct {
	hashname string
	reply    chan *peer_t
}

func (cmd *cmd_peer_lookup) exec(s *Switch) error {
	cmd.reply <- s.known_peers[cmd.hashname]
	close(cmd.reply)
	return nil
}
