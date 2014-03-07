package telehash

import (
	"encoding/json"
	"github.com/telehash/gogotelehash/net"
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

func encode_net_paths(n net_paths) (raw_net_paths, error) {
	raw := make([]json.RawMessage, len(n))

	for i, np := range n {
		data, err := net.EncodePath(np.Network, np.Address)
		if err != nil {
			return nil, err
		}

		raw[i] = json.RawMessage(data)
	}

	return raw, nil
}

func decode_net_paths(raw raw_net_paths) (net_paths, error) {
	paths := make(net_paths, 0, len(raw))

	for _, data := range raw {
		n, addr, err := net.DecodePath(data)
		if err != nil {
			continue // drop invalid netpaths
		}

		paths = append(paths, &net_path{Network: n, Address: addr})
	}

	return paths, nil
}
