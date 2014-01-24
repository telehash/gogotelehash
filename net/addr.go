package net

import (
	"encoding/json"
	"fmt"
)

type Addr interface {
	PublishWithSeek() bool
	PublishWithPath() bool
	PublishWithPeer() bool
	PublishWithConnect() bool
	NeedNatHolePunching() bool

	DefaultPriority() int

	EqualTo(other Addr) bool
	String() string
}

var (
	see_encoders  = map[string]func(Addr) ([]string, error){}
	see_decoders  = map[string]func([]string) (Addr, error){}
	path_encoders = map[string]func(Addr) ([]byte, error){}
	path_decoders = map[string]func([]byte) (Addr, error){}
)

func EncodeSee(net string, addr Addr) ([]string, error) {
	if f, p := see_encoders[net]; p {
		return f(addr)
	}
	return nil, nil
}

func DecodeSee(fields []string) (string, Addr, error) {
	for net, f := range see_decoders {
		addr, err := f(fields)
		if err == nil {
			return net, addr, nil
		}
	}
	return "", nil, nil
}

func DecodePath(data []byte) (string, Addr, error) {
	var (
		typ struct {
			Type string `json:"type"`
		}
	)

	err := json.Unmarshal(data, &typ)
	if err != nil {
		return "", nil, err
	}

	f, ok := path_decoders[typ.Type]
	if !ok {
		return "", nil, fmt.Errorf("Unknown type %q", typ.Type)
	}

	addr, err := f(data)
	if err != nil {
		return "", nil, err
	}

	return typ.Type, addr, nil
}

func EncodePath(net string, addr Addr) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	f, ok := path_encoders[net]
	if !ok {
		return nil, fmt.Errorf("Unknown type %q", net)
	}

	data, err = f(addr)
	if err != nil {
		return nil, err
	}

	len_type := len(net)
	data2 := make([]byte, len(data)+len_type+10)
	data2[0] = data[0]
	copy(data2[1:], "\"type\":\"")
	copy(data2[9:], net)
	copy(data2[len_type+9:], "\",")
	copy(data2[len_type+11:], data[1:])

	return data2, nil
}

func RegisterSeeEncoder(net string, f func(Addr) ([]string, error)) {
	if _, p := see_encoders[net]; p {
		panic(fmt.Sprintf("network %q already exists", net))
	}

	see_encoders[net] = f
}

func RegisterSeeDecoder(net string, f func([]string) (Addr, error)) {
	if _, p := see_decoders[net]; p {
		panic(fmt.Sprintf("network %q already exists", net))
	}

	see_decoders[net] = f
}

func RegisterPathEncoder(net string, f func(Addr) ([]byte, error)) {
	if _, p := path_encoders[net]; p {
		panic(fmt.Sprintf("network %q already exists", net))
	}

	path_encoders[net] = f
}

func RegisterPathDecoder(net string, f func([]byte) (Addr, error)) {
	if _, p := path_decoders[net]; p {
		panic(fmt.Sprintf("network %q already exists", net))
	}

	path_decoders[net] = f
}
