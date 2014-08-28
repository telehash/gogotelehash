// Telehash: Length-Object-Binary Encoding (Packet Format).
//
// Reference
//
// https://github.com/telehash/telehash.org/blob/v3/v3/lob/README.md
package lob

import (
	"encoding/binary"
	"encoding/json"
	"errors"
)

var ErrInvalidPacket = errors.New("lob: invalid packet")

type Packet struct {
	Head       []byte
	Body       []byte
	jsonHeader Header
}

func Decode(p []byte) (*Packet, error) {
	var (
		length int
		head   []byte
		dict   Header
		body   []byte
	)

	if len(p) < 2 {
		return nil, ErrInvalidPacket
	}

	length = int(binary.BigEndian.Uint16(p))
	if length+2 > len(p) {
		return nil, ErrInvalidPacket
	}

	head = p[2 : 2+length]
	if len(head) == 0 {
		head = nil
	}

	body = p[2+length:]
	if len(body) == 0 {
		body = nil
	}

	if len(head) >= 7 {
		err := json.Unmarshal(head, &dict)
		if err != nil {
			return nil, ErrInvalidPacket
		}
		head = nil
	}

	return &Packet{Head: head, jsonHeader: dict, Body: body}, nil
}

func Encode(pkt *Packet) ([]byte, error) {
	var (
		head []byte
		body []byte
		p    []byte
		err  error
	)

	if pkt == nil {
		return []byte{0, 0}, nil
	}

	if len(pkt.jsonHeader) > 0 {
		head, err = json.Marshal(pkt.jsonHeader)
		if err != nil {
			return nil, err
		}
		if len(head) < 7 {
			return nil, ErrInvalidPacket
		}
	} else if len(pkt.Head) > 0 {
		head = pkt.Head
		if len(head) >= 7 {
			return nil, ErrInvalidPacket
		}
	}

	if len(pkt.Body) > 0 {
		body = pkt.Body
	}

	p = make([]byte, 2+len(head)+len(body))
	binary.BigEndian.PutUint16(p, uint16(len(head)))
	copy(p[2:], head)
	copy(p[2+len(head):], body)

	return p, nil
}

func (p *Packet) Header() Header {
	if p.jsonHeader == nil {
		p.jsonHeader = make(Header)
	}
	return p.jsonHeader
}

type Header map[string]interface{}

func (h Header) Get(k string) interface{} {
	if h == nil {
		return nil
	}
	return h[k]
}

func (h Header) Set(k string, v interface{}) {
	if h == nil {
		return
	}
	h[k] = v
}

func (h Header) GetString(k string) (string, bool) {
	x, ok := h.Get(k).(string)
	if !ok {
		return "", false
	}
	return x, true
}

func (h Header) SetString(k string, v string) {
	h.Set(k, v)
}

func (h Header) GetInt(k string) (int, bool) {
	x, ok := h.Get(k).(int)
	if !ok {
		return 0, false
	}
	return x, true
}

func (h Header) SetInt(k string, v int) {
	h.Set(k, v)
}

func (h Header) GetUint32(k string) (uint32, bool) {
	x, ok := h.GetInt(k)
	if !ok || x < 0 {
		return 0, false
	}
	return uint32(x), true
}

func (h Header) SetUint32(k string, v uint32) {
	h.SetInt(k, int(v))
}
