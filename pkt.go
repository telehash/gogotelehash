package telehash

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
)

func form_packet(header interface{}, body []byte) ([]byte, error) {
	var (
		buf = bytes.NewBuffer(make([]byte, 0, 1500))
	)

	// make room for the length
	buf.WriteByte(0)
	buf.WriteByte(0)

	// write the header
	err := json.NewEncoder(buf).Encode(header)
	if err != nil {
		return nil, err
	}

	// get the header length
	l := buf.Len() - 2

	// write the body
	if len(body) > 0 {
		buf.Write(body)
	}

	// get the packet
	data := buf.Bytes()

	// put the header length
	binary.BigEndian.PutUint16(data[0:2], uint16(l))

	return data, nil
}

func parse_packet(in []byte, header interface{}, body []byte) ([]byte, error) {
	l := int(binary.BigEndian.Uint16(in[:2]))
	body_len := len(in) - (l + 2)

	err := json.NewDecoder(bytes.NewReader(in[2 : 2+l])).Decode(header)
	if err != nil {
		return nil, err
	}

	// no body
	if body_len == 0 {
		return nil, nil
	}

	if body == nil {
		body = make([]byte, body_len)
	} else {
		body = body[:body_len]
	}

	copy(body, in[l+2:])

	return body, nil
}
