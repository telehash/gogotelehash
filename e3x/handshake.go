package e3x

import (
	"reflect"

	"github.com/telehash/gogotelehash/e3x/cipherset"
	"github.com/telehash/gogotelehash/internal/lob"
)

var handshakeTypes = map[string]reflect.Type{}

func RegisterHandshakeType(i Handshake) {
	if _, p := handshakeTypes[i.Type()]; p {
		panic("handshake is already registered: " + i.Type())
	}

	t := reflect.TypeOf(i)
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Interface {
		t = t.Elem()
	}

	handshakeTypes[i.Type()] = t
}

type Handshake interface {
	Type() string

	EncodeHandshake() (*lob.Packet, error)
	DecodeHandshake(pkt *lob.Packet) error
}

func encodeHandshake(h Handshake) (*lob.Packet, error) {
	if h == nil {
		return nil, InvalidHandshakeError("")
	}

	pkt, err := h.EncodeHandshake()
	if err != nil {
		return nil, err
	}

	if h.Type() != "key" {
		hdr := pkt.Header()
		hdr.Type, hdr.HasType = h.Type(), true
	}

	return pkt, nil
}

func decodeHandshake(pkt *lob.Packet) (Handshake, error) {
	hdr := pkt.Header()

	if !hdr.HasType {
		hdr.HasType, hdr.Type = true, "key"
	}

	t, ok := handshakeTypes[hdr.Type]
	if !ok {
		return nil, InvalidHandshakeError("unkown type: " + hdr.Type)
	}

	h := reflect.New(t).Interface().(Handshake)
	err := h.DecodeHandshake(pkt)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func init() {
	RegisterHandshakeType(&cipherset.KeyHandshake{})
}
