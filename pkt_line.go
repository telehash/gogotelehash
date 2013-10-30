package telehash

import (
	"encoding/hex"
)

type pkt_line struct {
	Type string `json:"type"`
	Line string `json:"line"`
	Iv   string `json:"iv"`
}

func (l *line_t) send_pkt(pkt []byte) error {
	iv, err := make_rand(16)
	if err != nil {
		return err
	}

	pkt, err = enc_AES_256_CTR(l.enc_key, iv, pkt)
	if err != nil {
		return err
	}

	pkt, err = form_packet(pkt_line{
		Type: "line",
		Line: hex.EncodeToString(l.LineIn),
		Iv:   hex.EncodeToString(iv),
	}, pkt)
	if err != nil {
		return err
	}

	l._switch.o_queue <- pkt_udp_t{l.peer.addr, pkt}
	return nil
}

func (l *line_t) handle_pkt(pkt []byte) {
	var (
		header pkt_line
		body   = make([]byte, 1500)
		iv     []byte
		err    error
	)

	body, err = parse_packet(pkt, &header, body)
	if err != nil {
		Log.Debugf("dropped packet: %+q (error: %s)", pkt, err)
		return
	}

	iv, err = hex.DecodeString(header.Iv)
	if err != nil {
		Log.Debugf("dropped packet: %+q (error: %s)", pkt, err)
		return
	}

	body, err = dec_AES_256_CTR(l.dec_key, iv, body)
	if err != nil {
		Log.Debugf("dropped packet: %+q (error: %s)", pkt, err)
		return
	}

	Log.Debugf("rcv line pkt: %+q", body)
	// TODO: handle c
}
