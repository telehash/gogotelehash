package telehash

import (
	"crypto/rsa"
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

type peer_t struct {
	hashname string
	addr     *net.UDPAddr
	pubkey   *rsa.PublicKey
}

type Switch struct {
	identity   *rsa.PrivateKey
	hashname   string
	open_delta time.Duration // max open.at skew
	addr       string
	err        error

	conn        *net.UDPConn
	known_peers map[string]*peer_t
	i_queue     chan pkt_udp_t
	o_queue     chan pkt_udp_t
	c_queue     chan command_i
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
		i_queue:     make(chan pkt_udp_t),
		o_queue:     make(chan pkt_udp_t),
		c_queue:     make(chan command_i),
	}

	return s, nil
}

func (s *Switch) RegisterPeer(addr string, pub *rsa.PublicKey) error {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	hashname, err := hashname_from_RSA(pub)
	if err != nil {
		return err
	}

	s.c_queue <- &cmd_peer_register{
		peer: &peer_t{
			hashname: hashname,
			addr:     udp_addr,
			pubkey:   pub,
		},
	}

	return nil
}

func (s *Switch) Run() error {
	udp_addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	upd_conn, err := net.ListenUDP("udp", udp_addr)
	if err != nil {
		return err
	}

	s.conn = upd_conn

	go s.send_loop()
	go s.read_loop()
	go s.command_loop()

	for i := 0; i < runtime.NumCPU(); i++ {
		go s.dispatch_loop()
	}

	// TODO: wait for shutdown
	return s.err
}

func (s *Switch) Close() error {
	close(s.i_queue)
	close(s.c_queue)
	close(s.o_queue)
	return s.err
}

func (s *Switch) read_loop() {
	for {
		buf := make([]byte, 1500)
		count, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			// Read failed; note the error and shutdown
			s.err = err
			return
		}

		s.i_queue <- pkt_udp_t{addr: addr, data: buf[:count]}
	}
}

func (s *Switch) send_loop() {
	for pkt := range s.o_queue {
		_, err := s.conn.WriteToUDP(pkt.data, pkt.addr)
		if err != nil {
			// Read failed; note the error and shutdown
			s.err = err
			s.Close()
			return
		}
	}
}

func (s *Switch) command_loop() {
	for cmd := range s.c_queue {
		err := cmd.exec(s)
		if err != nil {
			// Command failed; note the error and shutdown
			s.err = err
			s.Close()
			return
		}
	}
}

func (s *Switch) dispatch_loop() {
	var (
		body = make([]byte, 1500)
		err  error
	)

	for pkt := range s.i_queue {
		var (
			header struct {
				Type string `json:"type"`
			}
		)

		_, err = parse_packet(pkt.data, &header, body)
		if err != nil {
			// failed to parse packet; drop it
			continue
		}

		switch header.Type {
		case "open":
			s.c_queue <- &cmd_open_i{pkt}
		default:
			// failed to parse packet; drop it
		}
	}
}

type cmd_peer_register struct {
	peer *peer_t
}

func (cmd *cmd_peer_register) exec(s *Switch) error {
	s.known_peers[cmd.peer.hashname] = cmd.peer
	return nil
}
