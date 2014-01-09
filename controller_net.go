package telehash

import (
	"github.com/fd/go-util/log"
	"net"
	"sync"
	"sync/atomic"
)

type net_controller struct {
	sw   *Switch
	conn *net.UDPConn
	wg   sync.WaitGroup
	log  log.Logger
	deny map[string]bool

	num_pkt_snd     uint64
	num_pkt_rcv     uint64
	num_err_pkt_snd uint64
	num_err_pkt_rcv uint64
}

func net_controller_open(sw *Switch) (*net_controller, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", sw.addr)
	if err != nil {
		return nil, err
	}

	upd_conn, err := net.ListenUDP("udp", udp_addr)
	if err != nil {
		return nil, err
	}

	c := &net_controller{
		sw:   sw,
		conn: upd_conn,
		log:  sw.log.Sub(log_level_for("NET", log.DEFAULT), "net"),
		deny: make(map[string]bool),
	}

	c.wg.Add(1)
	go c._reader_loop()

	return c, nil
}

func (c *net_controller) GetPort() int {
	addr := c.conn.LocalAddr()
	if addr == nil {
		return -1
	}
	return addr.(*net.UDPAddr).Port
}

func (c *net_controller) PopulateStats(s *SwitchStats) {
	s.NumSendPackets += atomic.LoadUint64(&c.num_pkt_snd)
	s.NumSendPacketErrors += atomic.LoadUint64(&c.num_err_pkt_snd)
	s.NumReceivedPackets += atomic.LoadUint64(&c.num_pkt_rcv)
	s.NumReceivedPacketErrors += atomic.LoadUint64(&c.num_err_pkt_rcv)
}

func (c *net_controller) close() {
	c.conn.Close()
	c.wg.Wait()
}

func (c *net_controller) deny_from_net(addr string) {
	c.deny[addr] = true
}

func (c *net_controller) _reader_loop() {
	defer c.wg.Done()

	var (
		buf = make([]byte, 16*1024)
	)

	for {
		err := c._read_pkt(buf)
		if err == ErrUDPConnClosed {
			break
		}
		if err != nil {
			c.log.Debugf("dropped pkt: %s", err)
		}
	}
}

func (c *net_controller) _read_pkt(buf []byte) error {
	var (
		addr *net.UDPAddr
		pkt  *pkt_t
		err  error
	)

	// read the udp packet
	addr, err = _net_conn_read(c.conn, &buf)
	if err != nil {
		atomic.AddUint64(&c.num_err_pkt_rcv, 1)
		return err
	}

	if c.deny[addr.String()] {
		return nil
	}

	// unpack the outer packet
	netpath := net_pathFromAddr(addr)
	pkt, err = parse_pkt(buf, nil, netpath)
	if err != nil {
		atomic.AddUint64(&c.num_err_pkt_rcv, 1)
		return err
	}

	c.log.Debugf("rcv pkt: addr=%s hdr=%+v",
		pkt.netpath, pkt.hdr)

	err = c.sw.rcv_pkt(pkt)
	if err != nil {
		atomic.AddUint64(&c.num_err_pkt_rcv, 1)
		return err
	}

	atomic.AddUint64(&c.num_pkt_rcv, 1)
	return nil
}

func (c *net_controller) send_nat_breaker(peer *Peer) {
	for _, np := range peer.net_paths() {
		if np.Address.NeedNatHolePunching() {
			np.Send(c.sw, &pkt_t{})
		}
	}
}

func _net_conn_read(conn *net.UDPConn, bufptr *[]byte) (*net.UDPAddr, error) {
	var (
		err  error
		addr *net.UDPAddr
		n    int
		buf  = *bufptr
	)

	n, addr, err = conn.ReadFromUDP(buf)

	if _net_conn_is_closed_err(err) {
		return nil, ErrUDPConnClosed
	}

	if err != nil {
		return nil, err
	}

	if n == 0 {
		return nil, errEmptyPkt
	}

	buf = buf[:n]
	*bufptr = buf

	return addr, nil
}

func _net_conn_write(conn *net.UDPConn, addr *net.UDPAddr, data []byte) error {
	var (
		err error
	)

	_, err = conn.WriteToUDP(data, addr)

	if _net_conn_is_closed_err(err) {
		err = ErrUDPConnClosed
	}

	return err
}

func _net_conn_is_closed_err(err error) bool {
	if err == nil {
		return false
	}

	const s = "use of closed network connection"

	switch v := err.(type) {
	case *net.OpError:
		return _net_conn_is_closed_err(v.Err)
	default:
		return s == v.Error()
	}
}
