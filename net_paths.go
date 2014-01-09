package telehash

import (
	"encoding/json"
)

type net_paths []*net_path

func (n net_paths) FirstOfType(t string) *net_path {

	for _, np := range n {
		if np.Network == t {
			return np
		}
	}

	return nil
}

func (n net_paths) MarshalJSON() ([]byte, error) {
	raw := make([]json.RawMessage, len(n))

	for i, np := range n {
		data, err := encode_net_path(np)
		if err != nil {
			return nil, err
		}

		raw[i] = json.RawMessage(data)
	}

	return json.Marshal(raw)
}

func (n *net_paths) UnmarshalJSON(data []byte) error {
	var (
		raw []json.RawMessage
	)

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	paths := make(net_paths, 0, len(raw))

	for _, data := range raw {
		np, err := decode_net_path(data)
		if err != nil {
			continue // drop invalid netpaths
		}

		paths = append(paths, np)
	}

	*n = paths
	return nil
}
