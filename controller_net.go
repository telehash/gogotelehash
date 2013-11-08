package telehash

import (
	"net"
	"runtime"
)

const (
	c_ClosedNet = "use of closed network connection"
)

type net_controller struct {
	conn   *net.UDPConn
	lines  *line_controller
	closed bool
}

func (h *net_controller) close() {
	h.conn.Close()
}

func net_controller_open(addr string) (*net_controller, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	upd_conn, err := net.ListenUDP("udp", udp_addr)
	if err != nil {
		return nil, err
	}

	h := &net_controller{
		conn: upd_conn,
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go h._reader_loop()
	}

	return h, nil
}

func (h *net_controller) Send(to Hashname, pkt *pkt_t) error {
	return h._snd_pkt(to, pkt)
}

func (h *net_controller) _reader_loop() {
	var (
		buf = make([]byte, 16*1024)
	)

	for {
		err := h._rcv_pkt(buf)
		if err == ErrUDPConnClosed {
			break
		}
		if err != nil {
			Log.Debugf("dropped pkt: %s", err)
		}
	}
}

func (h *net_controller) _rcv_pkt(buf []byte) error {
	var (
		addr *net.UDPAddr
		pkt  *pkt_t
		err  error
	)

	// read the udp packet
	addr, err = _net_conn_read(h.conn, &buf)
	if err != nil {
		return err
	}

	// unpack the outer packet
	pkt, err = _pkt_unmarshal(buf, addr)
	if err != nil {
		return err
	}

	// pass through line handler
	// (returns nil in case of an open pkt)
	pkt, err = h.lines.rcv_pkt(pkt)
	if err != nil {
		return err
	}
	if pkt == nil {
		return nil
	}

	return nil
}

func (h *net_controller) _snd_pkt(to Hashname, pkt *pkt_t) error {
	var (
		data []byte
		err  error
	)

	// pass through line handler
	// (this will also open a line if it is not already openend)
	// (open packets fall through)
	pkt, err = h.lines.snd_pkt(to, pkt)
	if err != nil {
		return err
	}

	// marshal the packet
	data, err = _pkt_marshal(pkt)
	if err != nil {
		return err
	}

	// send the packet
	err = _net_conn_write(h.conn, pkt.addr, data)
	if err != nil {
		return err
	}

	return err
}

func _pkt_unmarshal(data []byte, addr *net.UDPAddr) (*pkt_t, error) {
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
