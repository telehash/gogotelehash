package telehash

import (
	"encoding/json"
	"fmt"
)

func (s *Switch) decode_net_path(data []byte) (*net_path, error) {
	var (
		typ struct {
			Type string `json:"type"`
		}
	)

	err := json.Unmarshal(data, &typ)
	if err != nil {
		return nil, err
	}

	if typ.Type == "relay" {
		addr := &relay_addr{}
		err := json.Unmarshal(data, &addr)
		if err != nil {
			return nil, err
		}

		return &net_path{Network: typ.Type, Address: addr}, nil
	}

	t, ok := s.transports[typ.Type]
	if !ok {
		return nil, fmt.Errorf("Unknown type %q", typ.Type)
	}

	addr, err := t.DecodeAddr(data)
	if err != nil {
		return nil, err
	}

	return &net_path{Network: typ.Type, Address: addr}, nil
}

func (s *Switch) encode_net_path(n *net_path) ([]byte, error) {
	var (
		data []byte
		err  error
	)

	if n.Network == "relay" {
		data, err = json.Marshal(n.Address)
		if err != nil {
			return nil, err
		}

	} else {
		t, ok := s.transports[n.Network]
		if !ok {
			return nil, fmt.Errorf("Unknown type %q", n.Network)
		}

		data, err = t.EncodeAddr(n.Address)
		if err != nil {
			return nil, err
		}
	}

	len_type := len(n.Network)
	data2 := make([]byte, len(data)+len_type+10)
	data2[0] = data[0]
	copy(data2[1:], "\"type\":\"")
	copy(data2[9:], n.Network)
	copy(data2[len_type+9:], "\",")
	copy(data2[len_type+11:], data[1:])

	return data2, nil
}
