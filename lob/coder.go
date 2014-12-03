// Package lob implemnets the Length-Object-Binary encoding (Packet Format).
//
// Reference
//
// https://github.com/telehash/telehash.org/blob/v3/v3/lob/README.md
package lob

import (
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/telehash/gogotelehash/util/bufpool"
	"github.com/telehash/gogotelehash/util/tracer"
)

// ErrInvalidPacket is returned by Decode
var ErrInvalidPacket = errors.New("lob: invalid packet")

// Packet represents a packet.
type Packet struct {
	raw  []byte
	json Header
	Head []byte
	Body []byte
	TID  tracer.ID
}

// Decode a packet
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

	return &Packet{raw: p, Head: head, json: dict, Body: body}, nil
}

// Encode a packet
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

	if pkt.json != nil && len(pkt.json) > 0 {
		head, err = json.Marshal(pkt.json)
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

	p = bufpool.GetBuffer()
	p = p[:2+len(head)+len(body)]
	binary.BigEndian.PutUint16(p, uint16(len(head)))
	copy(p[2:], head)
	copy(p[2+len(head):], body)

	return p, nil
}

// Header returns the packet JSON header if present.
func (p *Packet) Header() Header {
	if p.Head != nil {
		return nil
	}
	if p.json == nil {
		p.json = make(Header, 10)
	}
	return p.json
}

// Free the packets backing buffer back to the buffer pool.
func (p *Packet) Free() {
	if p == nil {
		return
	}
	if p.raw != nil {
		bufpool.PutBuffer(p.raw)
	}
}

// Header represents a packet header.
type Header map[string]interface{}

// Get the value for key k. found is false if k is not present.
func (h Header) Get(k string) (v interface{}, found bool) {
	if h == nil {
		return nil, false
	}
	v, found = h[k]
	return v, found
}

// Set a the header k to v.
func (h Header) Set(k string, v interface{}) {
	if h == nil {
		return
	}
	h[k] = v
}

// GetString returns the string value for key k. found is false if k is not present.
func (h Header) GetString(k string) (v string, found bool) {
	y, ok := h.Get(k)
	if !ok {
		return "", false
	}
	x, ok := y.(string)
	if !ok {
		return "", false
	}
	return x, true
}

// SetString a the header k to v.
func (h Header) SetString(k string, v string) {
	h.Set(k, v)
}

// GetBool returns the bool value for key k. found is false if k is not present.
func (h Header) GetBool(k string) (v bool, found bool) {
	y, ok := h.Get(k)
	if !ok {
		return false, false
	}
	x, ok := y.(bool)
	if !ok {
		return false, false
	}
	return x, true
}

// SetBool a the header k to v.
func (h Header) SetBool(k string, v bool) {
	h.Set(k, v)
}

// GetInt returns the int value for key k. found is false if k is not present.
func (h Header) GetInt(k string) (v int, found bool) {
	y, ok := h.Get(k)
	if !ok {
		return 0, false
	}
	switch x := y.(type) {
	case int:
		return x, true
	case int8:
		return int(x), true
	case int16:
		return int(x), true
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case uint:
		return int(x), true
	case uint8:
		return int(x), true
	case uint16:
		return int(x), true
	case uint32:
		return int(x), true
	case uint64:
		return int(x), true
	case float32:
		return int(x), true
	case float64:
		return int(x), true
	default:
		return 0, false
	}
}

// SetInt a the header k to v.
func (h Header) SetInt(k string, v int) {
	h.Set(k, v)
}

// GetUint32 returns the uint32 value for key k. found is false if k is not present.
func (h Header) GetUint32(k string) (v uint32, found bool) {
	x, ok := h.GetInt(k)
	if !ok || x < 0 {
		return 0, false
	}
	return uint32(x), true
}

// SetUint32 a the header k to v.
func (h Header) SetUint32(k string, v uint32) {
	h.SetInt(k, int(v))
}

// GetUint32Slice returns the []uint32 value for key k. found is false if k is not present.
func (h Header) GetUint32Slice(k string) (v []uint32, found bool) {
	y, ok := h.Get(k)
	if !ok {
		return nil, false
	}
	x, ok := y.([]interface{})
	if !ok {
		return nil, false
	}
	z := make([]uint32, len(x))
	for i, a := range x {
		b, ok := a.(int)
		if !ok || b < 0 {
			return nil, false
		}
		z[i] = uint32(b)
	}
	return z, true
}

// SetUint32Slice a the header k to v.
func (h Header) SetUint32Slice(k string, v []uint32) {
	h.Set(k, v)
}
