package telehash

import (
	"github.com/fd/go-util/log"
	"net"
	"runtime"
	"sync"
)

const (
	c_ClosedNet = "use of closed network connection"
)

type net_controller struct {
	sw   *Switch
	conn *net.UDPConn
	wg   sync.WaitGroup
	log  log.Logger
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
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		c.wg.Add(1)
		go c._reader_loop()
	}

	return c, nil
}

func (c *net_controller) close() {
	c.conn.Close()
	c.wg.Wait()
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
		// c.log.Debugf("rcv pkt err=%s addr=%s", err, addr)
		return err
	}

	// c.log.Debugf("udp rcv pkt=(%d bytes)", len(buf))

	// unpack the outer packet
	pkt, err = _pkt_unmarshal(buf, addr_t{addr: addr})
	if err != nil {
		c.log.Debugf("rcv pkt step=1 err=%s pkt=%#v", err, pkt)
		return err
	}

	return c._rcv_pkt(pkt)
}

func (c *net_controller) _rcv_pkt(pkt *pkt_t) error {
	var (
		err error
	)

	c.log.Debugf("rcv pkt: addr=%s hdr=%+v",
		pkt.addr, pkt.hdr)

	// pass through line handler
	err = c.sw.peers.rcv_pkt(pkt)
	if err != nil {
		c.log.Debugf("rcv pkt step=2 addr=%s err=%s pkt=%#v", pkt.addr.addr.String(), err, pkt)
		return err
	}

	return nil
}

func (c *net_controller) snd_pkt(pkt *pkt_t) error {
	var (
		data []byte
		err  error
	)

	c.log.Debugf("snd pkt: addr=%s hdr=%+v",
		pkt.addr, pkt.hdr)

	// c.log.Debugf("tsh snd outer-pkt=%+v", pkt.hdr)

	// marshal the packet
	data, err = _pkt_marshal(pkt)
	if err != nil {
		return err
	}

	// send the packet
	err = _net_conn_write(c.conn, pkt.addr.addr, data)
	if err != nil {
		return err
	}

	// c.log.Debugf("udp snd pkt=(%d bytes)", len(data))

	return err
}

func (c *net_controller) send_nat_breaker(addr *net.UDPAddr) error {
	return _net_conn_write(c.conn, addr, []byte("hello"))
}

func _pkt_unmarshal(data []byte, addr addr_t) (*pkt_t, error) {
	return parse_pkt(data, addr)
}

func _pkt_marshal(pkt *pkt_t) ([]byte, error) {
	return pkt.format_pkt()
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
