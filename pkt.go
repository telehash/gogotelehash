package telehash

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
)

type pkt_t struct {
	buf       []byte
	hdr       []byte
	hdr_value interface{}
	body      []byte

	priv_hdr struct {
		Type   string  `json:"type,omitempty"`
		Line   string  `json:"line,omitempty"`
		Iv     string  `json:"iv,omitempty"`
		Open   string  `json:"open,omitempty"`
		Sig    string  `json:"sig,omitempty"`
		C      string  `json:"c,omitempty"`
		To     string  `json:"to,omitempty"`
		At     int64   `json:"at,omitempty"`
		Family string  `json:"family,omitempty"`
		Seq    seq_t   `json:"seq,omitempty"`
		Ack    seq_t   `json:"ack,omitempty"`
		Miss   []seq_t `json:"miss,omitempty"`
		End    bool    `json:"end,omitempty"`
		Err    string  `json:"err,omitempty"`
	}

	peer    *Peer
	netpath *net_path
}

func encode_packet(pkt *pkt_t) ([]byte, error) {
	var (
		header_data = buffer_pool_acquire()[:0]
		buf         *bytes.Buffer
		offset      int
		err         error
	)

	{ // write private headers
		buf = bytes.NewBuffer(header_data)
		err = json.NewEncoder(buf).Encode(&pkt.priv_hdr)
		if err != nil {
			buffer_pool_release(header_data)
			return nil, err
		}

		offset = buf.Len() - 1
		header_data = header_data[:offset]
	}

	if pkt.hdr_value != nil {
		offset -= 1
		buf = bytes.NewBuffer(header_data[offset:offset])
		err = json.NewEncoder(buf).Encode(pkt.hdr_value)
		if err != nil {
			buffer_pool_release(header_data)
			return nil, err
		}
		if header_data[offset] != '{' {
			buffer_pool_release(header_data)
			return nil, errInvalidPkt
		}

		if buf.Len() == 3 {
			header_data[offset] = '}'
			offset += 1
		} else {
			header_data[offset] = ','
			offset += buf.Len() - 1
		}

		header_data = header_data[:offset]
	}

	data, err := encode_raw_packet(header_data, pkt.body)
	buffer_pool_release(header_data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func encode_raw_packet(hdr, body []byte) ([]byte, error) {
	var (
		len_hdr  = len(hdr)
		len_body = len(body)
		buf      = buffer_pool_acquire()
	)

	binary.BigEndian.PutUint16(buf, uint16(len_hdr))
	if len_hdr > 0 {
		copy(buf[2:], hdr)
	}
	if len_body > 0 {
		copy(buf[2+len_hdr:], body)
	}

	if 2+len_hdr+len_body > cap(buf) {
		return nil, errInvalidPkt
	}

	return buf[0 : 2+len_hdr+len_body], nil
}

func decode_packet(data []byte) (*pkt_t, error) {
	// get a packet from the pool
	pkt := packet_pool_acquire()

	// copy the packet data
	pkt.buf = pkt.buf[:len(data)]
	copy(pkt.buf, data)

	hdr, body, err := decode_raw_packet(pkt.buf)
	if err != nil {
		packet_pool_release(pkt)
		return nil, err
	}

	pkt.hdr = hdr
	pkt.body = body

	err = json.Unmarshal(pkt.hdr, &pkt.priv_hdr)
	if err != nil {
		packet_pool_release(pkt)
		return nil, err
	}

	return pkt, nil
}

func decode_raw_packet(pkt []byte) (hdr, body []byte, err error) {
	var (
		len_pkt  = len(pkt)
		len_hdr  int
		len_body int
	)

	if len_pkt == 0 {
		return nil, nil, nil
	}

	if len_pkt < 2 {
		return nil, nil, errInvalidPkt
	}

	len_hdr = int(binary.BigEndian.Uint16(pkt))
	len_body = len_pkt - len_hdr - 2

	if len_body < 0 {
		return nil, nil, errInvalidPkt
	}

	if len_hdr > 0 {
		hdr = pkt[2 : 2+len_hdr]
	}

	if len_body > 0 {
		body = pkt[2+len_hdr:]
	}

	return hdr, body, nil
}
