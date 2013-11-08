package telehash

import (
	"net"
	"runtime"
	"strings"
	"time"
)

type net_handler struct {
	conn *net.UDPConn
	rcv  chan *pkt_t
}

func (n *net_handler) _close_rcv() {
	defer func() { recover() }()
	close(n.rcv)
}

func (h *net_handler) reader_loop() {
	var (
		n    int
		addr *net.UDPAddr
		err  error
		data []byte
		buf  = make([]byte, 64*1024)
		pkt  *pkt_t
	)

	defer h._close_rcv()

	for {
		n, addr, err = h.conn.ReadFromUDP(buf)

		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}

			Log.Debugf("dropped pkt: %s", err)
			continue
		}

		if n > 0 {
			data = make([]byte, n)
			copy(data, buf)
		} else {
			continue
		}

		pkt, err = parse_pkt(data, addr)
		if err != nil {
			Log.Debugf("dropped pkt: %s", err)
			continue
		}

		h.rcv <- pkt
	}
}

func net_handler_open(addr string) (*net_handler, error) {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	upd_conn, err := net.ListenUDP("udp", udp_addr)
	if err != nil {
		return nil, err
	}

	h := &net_handler{
		conn: upd_conn,
		rcv:  make(chan *pkt_t),
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go h.reader_loop()
	}

	return h, nil
}

func (h *net_handler) close() {
	h.conn.Close()
}

func (h *net_handler) send(pkt *pkt_t) error {

	data, err := pkt.format_pkt()
	if err != nil {
		return err
	}

	h.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))

	_, err = h.conn.WriteToUDP(data, pkt.addr)
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return ErrUDPConnClosed
	}

	return err

	// Log.Debugf("net: snd-pkt addr=%s size=%d", snd.addr, len(snd.data))
}
