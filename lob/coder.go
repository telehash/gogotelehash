// Package lob implemnets the Length-Object-Binary encoding (Packet Format).
//
// Reference
//
// https://github.com/telehash/telehash.org/blob/master/v3/lob.md
package lob

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// ErrInvalidPacket is returned if the data is not valid LOB encoding
var ErrInvalidPacket = errors.New("invalid lob Packet")

// ErrNonJSONHeader is returend if an emtpy or binary header is decoded as JSON
var ErrNonJSONHeader = errors.New("non JSON header, length is <7 bytes")

// ErrHeaderTooLong is returned if the header to be encoded is longer than what is supported by LOB
var ErrHeaderTooLong = fmt.Errorf("header is too long, must be less then %d bytes", math.MaxUint16)

// Header represents a LOB header
// It can either be emtpy, plain binary data, or JSON
type Header []byte

// DecodeJSON will try to decode the given Header as JSON and populate the passed in struct v
// It will return a ErrNonJSONHeader if the lenght of the header is < 7 bytes
// or it will return an error form encoding/json if the data is non valid JSON
func (h *Header) DecodeJSON(v interface{}) error {
	if len(*h) < 7 {
		return ErrNonJSONHeader
	}

	return json.Unmarshal(*h, &v)
}

// EncodeJSON encodes the given struct v as JSON and stores the binary representation in the Header
func (h *Header) EncodeJSON(v interface{}) (err error) {
	*h, err = json.Marshal(&v)
	if err != nil {
		return err
	}
	return nil
}

// Packet represents a Packet.
type Packet struct {
	Head Header
	Body []byte
}

// MarshalBinary encodes the Packte Header and Body into a LOB encoded byte array
// This array is in BigEndian (network order)
func (p *Packet) MarshalBinary() (data []byte, err error) {
	var b bytes.Buffer

	// Header length is always 2 bytes and big endian (network order)
	if len(p.Head) > math.MaxUint16 {
		return nil, ErrHeaderTooLong
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(p.Head)))

	b.Write(length)
	b.Write(p.Head)
	b.Write(p.Body)

	return b.Bytes(), nil
}

// UnmarshalBinary decodes a LOB encoded byte array into a Packet struct
func (p *Packet) UnmarshalBinary(data []byte) error {
	length := int(binary.BigEndian.Uint16(data[0:2]))

	if len(data) < length {
		return ErrInvalidPacket
	}
	p.Head = data[2 : length+2]

	p.Body = data[length+2:]

	return nil
}
