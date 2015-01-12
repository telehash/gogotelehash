// Package lob implemnets the Length-Object-Binary encoding (Packet Format).
//
// Reference
//
// https://github.com/telehash/telehash.org/blob/v3/v3/lob/README.md
package lob

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/internal/util/tracer"
)

// ErrInvalidPacket is returned by Decode
var ErrInvalidPacket = errors.New("lob: invalid packet")

var pktPool = sync.Pool{
	New: func() interface{} { return new(Packet) },
}

// Packet represents a packet.
type Packet struct {
	body   *bufpool.Buffer
	header Header
	TID    tracer.ID
}

// Header represents a packet header.
type Header struct {
	Bytes []byte `json:"-"`

	C       uint32   `json:"c,omitempty"`
	Type    string   `json:"type,omitempty"`
	End     bool     `json:"end,omitempty"`
	Err     string   `json:"err,omitempty"`
	At      uint32   `json:"at,omitempty"`
	Seq     uint32   `json:"seq,omitempty"`
	Ack     uint32   `json:"ack,omitempty"`
	Miss    []uint32 `json:"miss,omitempty"`
	HasC    bool     `json:"-"`
	HasType bool     `json:"-"`
	HasEnd  bool     `json:"-"`
	HasErr  bool     `json:"-"`
	HasAt   bool     `json:"-"`
	HasSeq  bool     `json:"-"`
	HasAck  bool     `json:"-"`
	HasMiss bool     `json:"-"`

	Extra map[string]interface{} `json:"extra,omitempty"`
}

func New(body []byte) *Packet {
	pkt := pktPool.Get().(*Packet)

	if len(body) > 0 {
		pkt.body = bufpool.New().Set(body)
	}

	return pkt
}

// Free the packets backing buffer back to the buffer pool.
func (p *Packet) Free() {
	if p == nil {
		return
	}

	p.body.Free()

	p.header = Header{}
	p.body = nil
	pktPool.Put(p)
}

// Header returns the packet JSON header if present.
func (p *Packet) Header() *Header {
	return &p.header
}

func (p *Packet) Body(buf []byte) []byte {
	return p.body.Get(buf)
}

func (p *Packet) BodyLen() int {
	return p.body.Len()
}

func (p *Packet) SetHeader(header Header) *Packet {
	p.header = header
	return p
}

func (p *Packet) String() string {
	return fmt.Sprintf("PKT{Header: %v, Body: %s}", &p.header, p.body)
}

func (p *Packet) GoString() string {
	return fmt.Sprintf("PKT{Header: %v, Body: %s}", &p.header, p.body)
}

// Decode a packet
func Decode(p *bufpool.Buffer) (*Packet, error) {
	var (
		length int
		head   []byte
		body   []byte
		bytes  = p.RawBytes()
	)

	if len(bytes) < 2 {
		return nil, ErrInvalidPacket
	}

	length = int(binary.BigEndian.Uint16(bytes))
	if length+2 > len(bytes) {
		return nil, ErrInvalidPacket
	}

	head = bytes[2 : 2+length]
	if len(head) == 0 {
		head = nil
	}

	pkt := pktPool.Get().(*Packet)

	body = bytes[2+length:]
	if len(body) > 0 {
		pkt.body = bufpool.New().Set(body)
	}

	if len(head) >= 7 {
		err := parseHeader(pkt.Header(), head)
		if err != nil {
			pkt.Free()
			return nil, ErrInvalidPacket
		}
	} else if len(head) > 0 {
		pkt.Header().Bytes = append(make([]byte, 0, len(head)), head...)
	}

	return pkt, nil
}

var byteBufferPool = sync.Pool{
	New: func() interface{} { return bytes.NewBuffer(make([]byte, 0, 1500)) },
}

// Encode a packet
func Encode(pkt *Packet) (*bufpool.Buffer, error) {
	var (
		p      *bufpool.Buffer
		hdrLen int
		err    error
	)

	if pkt == nil {
		return bufpool.New().SetLen(2), nil
	}

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.WriteByte(0)
	buf.WriteByte(0)

	if !pkt.header.IsZero() {
		if !pkt.header.IsBinary() {
			err = pkt.header.writeTo(buf)
			if err != nil {
				buf.Reset()
				byteBufferPool.Put(buf)
				return nil, err
			}
			hdrLen = buf.Len() - 2
			if hdrLen < 7 {
				buf.Reset()
				byteBufferPool.Put(buf)
				return nil, ErrInvalidPacket
			}
		} else {
			hdrLen = len(pkt.header.Bytes)
			if hdrLen >= 7 {
				buf.Reset()
				byteBufferPool.Put(buf)
				return nil, ErrInvalidPacket
			}
			buf.Write(pkt.header.Bytes)
		}
	}

	if pkt.body.Len() > 0 {
		pkt.body.WriteTo(buf)
	}

	p = bufpool.New()
	p.Set(buf.Bytes())
	binary.BigEndian.PutUint16(p.RawBytes(), uint16(hdrLen))

	buf.Reset()
	byteBufferPool.Put(buf)

	return p, nil
}

func (h *Header) writeTo(buf *bytes.Buffer) error {
	var first = true

	buf.WriteByte('{')

	if h.HasC {
		buf.Write(hdrC)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%d", h.C)
		first = false
	}

	if h.HasType {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrType)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%q", h.Type)
		first = false
	}

	if h.HasEnd {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrEnd)
		buf.WriteByte(':')
		if h.End {
			buf.Write(tokenTrue)
		} else {
			buf.Write(tokenFalse)
		}
		first = false
	}

	if h.HasErr {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrErr)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%q", h.Err)
		first = false
	}

	if h.HasAt {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrAt)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%d", h.At)
		first = false
	}

	if h.HasSeq {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrSeq)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%d", h.Seq)
		first = false
	}

	if h.HasAck {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrAck)
		buf.WriteByte(':')
		fmt.Fprintf(buf, "%d", h.Ack)
		first = false
	}

	if h.HasMiss && len(h.Miss) > 0 {
		if !first {
			buf.WriteByte(',')
		}
		buf.Write(hdrMiss)
		buf.WriteByte(':')
		buf.WriteByte('[')
		for i, m := range h.Miss {
			if i > 0 {
				buf.WriteByte(',')
			}
			fmt.Fprintf(buf, "%d", m)
		}
		buf.WriteByte(']')
		first = false
	}

	if len(h.Extra) > 0 {
		enc := json.NewEncoder(buf)
		for k, v := range h.Extra {
			if !first {
				buf.WriteByte(',')
			}

			fmt.Fprintf(buf, "%q", k)
			buf.WriteByte(':')
			err := enc.Encode(v)
			if err != nil {
				return err
			}
			first = false
		}
	}

	buf.WriteByte('}')
	return nil
}

// IsZero returns true when the header is the zero value or equivalent.
func (h *Header) IsZero() bool {
	return !h.HasC && !h.HasEnd && !h.HasType && !h.HasSeq && !h.HasAck && (!h.HasMiss || len(h.Miss) == 0) && len(h.Extra) == 0 && len(h.Bytes) == 0
}

func (h *Header) IsBinary() bool {
	return len(h.Bytes) != 0
}

// Get the value for key k. found is false if k is not present.
func (h *Header) Get(k string) (v interface{}, found bool) {
	if h == nil || h.Extra == nil {
		return nil, false
	}
	v, found = h.Extra[k]
	return v, found
}

// Set a the header k to v.
func (h *Header) Set(k string, v interface{}) {
	if h == nil {
		return
	}
	if h.Extra == nil {
		h.Extra = make(map[string]interface{})
	}
	h.Extra[k] = v
}

// GetString returns the string value for key k. found is false if k is not present.
func (h *Header) GetString(k string) (v string, found bool) {
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
func (h *Header) SetString(k string, v string) {
	h.Set(k, v)
}

// GetBool returns the bool value for key k. found is false if k is not present.
func (h *Header) GetBool(k string) (v bool, found bool) {
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
func (h *Header) SetBool(k string, v bool) {
	h.Set(k, v)
}

// GetInt returns the int value for key k. found is false if k is not present.
func (h *Header) GetInt(k string) (v int, found bool) {
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
func (h *Header) SetInt(k string, v int) {
	h.Set(k, v)
}

// GetUint32 returns the uint32 value for key k. found is false if k is not present.
func (h *Header) GetUint32(k string) (v uint32, found bool) {
	x, ok := h.GetInt(k)
	if !ok || x < 0 {
		return 0, false
	}
	return uint32(x), true
}

// SetUint32 a the header k to v.
func (h *Header) SetUint32(k string, v uint32) {
	h.SetInt(k, int(v))
}

// GetUint32Slice returns the []uint32 value for key k. found is false if k is not present.
func (h *Header) GetUint32Slice(k string) (v []uint32, found bool) {
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
func (h *Header) SetUint32Slice(k string, v []uint32) {
	h.Set(k, v)
}
