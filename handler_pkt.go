package telehash

import (
	"runtime"
)

type pkt_handler struct {
	conn *net_handler
	rcv  chan *pkt_t
}

func (h *pkt_handler) close_rcv_channel() {
	defer func() { recover() }()
}

func (h *pkt_handler) reader_loop() {
	defer h.close_rcv_channel()

	for rcv := range h.conn.rcv {

		// on error
		if rcv.err != nil {
			Log.Debugf("dropped pkt: %s", rcv.err)
			continue
		}

		pkt, err := parse_pkt(rcv.data, rcv.addr)
		if err != nil {
			Log.Debugf("dropped pkt: %s", rcv.err)
			continue
		}

		h.rcv <- pkt

	}
}

func pkt_handler_open(addr string) (*pkt_handler, error) {
	conn, err := net_handler_open(addr)
	if err != nil {
		return nil, err
	}

	h := &pkt_handler{
		conn: conn,
		rcv:  make(chan *pkt_t),
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go h.reader_loop()
	}

	return h, nil
}

func (h *pkt_handler) close() {
	h.conn.close()
}

func (h *pkt_handler) send(pkt *pkt_t) error {
	data, err := pkt.format_pkt()
	if err != nil {
		return err
	}

	return h.conn.send(pkt.addr, data)
}
