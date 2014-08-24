// Telehash: Length-Object-Binary Encoding (Packet Format)
//
// See: https://github.com/telehash/telehash.org/blob/558332cd82dec3b619d194d42b3d16618f077e0f/v3/lob/README.md
package lob

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
)

var ErrInvalidPacket = errors.New("lob: invalid packet")

type Packet struct {
	Head []byte
	Json interface{}
	Body []byte
}

func Decode(p []byte) (*Packet, error) {
	var (
		length int
		head   []byte
		dict   interface{}
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
		if reflect.TypeOf(dict).Kind() != reflect.Map {
			return nil, ErrInvalidPacket
		}
		head = nil
	}

	return &Packet{Head: head, Json: dict, Body: body}, nil
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

	if pkt.Json != nil {
		if reflect.TypeOf(pkt.Json).Kind() != reflect.Map {
			return nil, ErrInvalidPacket
		}

		head, err = json.Marshal(pkt.Json)
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
