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

func (c *net_controller) GetPort() int {
	addr := c.conn.LocalAddr()
	if addr == nil {
		return -1
	}
	return addr.(*net.UDPAddr).Port
}

func (c *net_controller) close() {
	c.conn.Close()
	c.wg.Wait()
}

func (c *net_controller) _reader_loop() {
	defer c.wg.Done()

	var (
		buf   = make([]byte, 16*1024)
		reply = make(chan *line_t)
	)

	for {
		err := c._read_pkt(buf, reply)
		if err == ErrUDPConnClosed {
			break
		}
		if err != nil {
			c.log.Debugf("dropped pkt: %s", err)
		}
	}
}

func (c *net_controller) _read_pkt(buf []byte, reply chan *line_t) error {
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
	pkt, err = parse_pkt(buf, addr_t{addr: addr})
	if err != nil {
		c.log.Debugf("rcv pkt step=1 err=%s pkt=%#v", err, pkt)
		return err
	}

	return c._rcv_pkt(pkt, reply)
}

func (c *net_controller) _rcv_pkt(pkt *pkt_t, reply chan *line_t) error {
	c.log.Debugf("rcv pkt: addr=%s hdr=%+v",
		pkt.addr, pkt.hdr)

	if pkt.hdr.Type == "line" {
		c.sw.main.get_active_line_chan <- cmd_line_get_active{pkt.hdr.Line, reply}
		if line := <-reply; line != nil {
			line.RcvLine(pkt)
			return nil
		} else {
			return errUnknownLine
		}
	}

	if pkt.hdr.Type == "open" {
		pub, err := decompose_open_pkt(c.sw.key, pkt)
		if err != nil {
			return err
		}

		c.sw.main.get_line_chan <- cmd_line_get{pub.hashname, pkt.addr, pub, reply}
		if line := <-reply; line != nil {
			line.RcvOpen(pub, pkt.addr)
			return nil
		} else {
			return errUnknownLine
		}
	}

	return errInvalidPkt
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
	data, err = pkt.format_pkt()
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
