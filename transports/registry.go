package transports

import (
	"encoding/json"
	"errors"
	"net"
	"reflect"
)

var ErrInvalidAddr = errors.New("invalid address")

type AddrMarshaler interface {
	net.Addr
	json.Marshaler
	json.Unmarshaler
}

var addressTypes = map[string]reflect.Type{}

// RegisterAddr registers a marshalable address type.
// Addr types that are expected to be communicated through telehash must be
// registered here.
func RegisterAddr(typ AddrMarshaler) {
	if typ == nil {
		panic("invalid address type")
	}
	if addressTypes[typ.Network()] != nil {
		panic("address type is already registered")
	}

	v := reflect.TypeOf(typ)
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	addressTypes[typ.Network()] = v
}

// DecodeAddr will decode an address from JSON.
// ErrInvalidAddr is returned when the address could not be decoded.
func DecodeAddr(p []byte) (net.Addr, error) {
	var desc struct {
		Type string `json:"type"`
	}

	err := json.Unmarshal(p, &desc)
	if err != nil {
		return nil, ErrInvalidAddr
	}

	t := addressTypes[desc.Type]
	if t == nil {
		return nil, ErrInvalidAddr
	}

	a := reflect.New(t).Interface().(AddrMarshaler)
	err = json.Unmarshal(p, &a)
	if err != nil {
		return nil, ErrInvalidAddr
	}

	return a, nil
}

func EncodeAddr(a net.Addr) ([]byte, error) {
	return json.Marshal(a)
}
