package telehash

import (
	"encoding/json"
)

type net_paths []*net_path
type raw_net_paths []json.RawMessage

func (n net_paths) FirstOfType(t string) *net_path {

	for _, np := range n {
		if np.Network == t {
			return np
		}
	}

	return nil
}

func (s *Switch) encode_net_paths(n net_paths) (raw_net_paths, error) {
	raw := make([]json.RawMessage, len(n))

	for i, np := range n {
		data, err := s.encode_net_path(np)
		if err != nil {
			return nil, err
		}

		raw[i] = json.RawMessage(data)
	}

	return raw, nil
}

func (s *Switch) decode_net_paths(raw raw_net_paths) (net_paths, error) {
	paths := make(net_paths, 0, len(raw))

	for _, data := range raw {
		np, err := s.decode_net_path(data)
		if err != nil {
			continue // drop invalid netpaths
		}

		paths = append(paths, np)
	}

	return paths, nil
}
