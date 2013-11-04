package telehash

import (
	"errors"
	"net"
	"strings"
	"time"
)

type net_handler struct {
	conn *net.UDPConn
	rcv  chan net_handler_rcv
	snd  chan net_handler_snd
}

type net_handler_snd struct {
	addr  *net.UDPAddr
	data  []byte
	reply chan error
}

type net_handler_rcv struct {
	addr *net.UDPAddr
	data []byte
	err  error
}

var ErrUDPConnClosed = errors.New("upd: connection closed")

func (h *net_handler) reader_loop() {
	var (
		n    int
		addr *net.UDPAddr
		err  error
		data []byte
		buf  = make([]byte, 64*1024)
	)

	defer close(h.rcv)

	for {
		n, addr, err = h.conn.ReadFromUDP(buf)
		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			return
		}

		if n > 0 {
			data = make([]byte, n)
			copy(data, buf)
		} else {
			data = nil
		}

		// Log.Debugf("net: rcv-pkt addr=%s size=%d", addr, len(data))

		h.rcv <- net_handler_rcv{
			addr: addr,
			data: data,
			err:  err,
		}
	}
}

func (h *net_handler) writer_loop() {
	for snd := range h.snd {

		h.conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		_, err := h.conn.WriteToUDP(snd.data, snd.addr)

		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			snd.reply <- ErrUDPConnClosed
			close(snd.reply)
			return
		}

		snd.reply <- err
		close(snd.reply)

		// Log.Debugf("net: snd-pkt addr=%s size=%d", snd.addr, len(snd.data))
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
		rcv:  make(chan net_handler_rcv),
		snd:  make(chan net_handler_snd),
	}

	go h.reader_loop()
	go h.writer_loop()

	return h, nil
}

func (h *net_handler) close() {
	h.conn.Close()
	close(h.snd)
	h.conn = nil
}

func (h *net_handler) send(addr *net.UDPAddr, data []byte) error {
	var (
		snd = net_handler_snd{
			addr:  addr,
			data:  data,
			reply: make(chan error, 1),
		}
	)

	if h.try_send(snd) {
		return <-snd.reply
	} else {
		return ErrUDPConnClosed
	}
}

func (h *net_handler) try_send(snd net_handler_snd) (ok bool) {
	ok = true

	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	h.snd <- snd
	return
}
