package telehash

import (
	"encoding/json"
	"reflect"
)

type NetPaths []NetPath

func (n NetPaths) FirstOfType(t NetPath) NetPath {
	rt := reflect.TypeOf(t)
	for rt.Kind() == reflect.Ptr {
		rt = rt.Elem()
	}

	for _, np := range n {
		npt := reflect.TypeOf(np)
		for npt.Kind() == reflect.Ptr {
			npt = npt.Elem()
		}

		if npt == rt {
			return np
		}
	}

	return nil
}

func (n NetPaths) MarshalJSON() ([]byte, error) {
	raw := make([]json.RawMessage, len(n))

	for i, np := range n {
		data, err := EncodeNetPath(np)
		if err != nil {
			return nil, err
		}

		raw[i] = json.RawMessage(data)
	}

	return json.Marshal(raw)
}

func (n *NetPaths) UnmarshalJSON(data []byte) error {
	var (
		raw []json.RawMessage
	)

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	paths := make(NetPaths, 0, len(raw))

	for _, data := range raw {
		np, err := DecodeNetPath(data)
		if err != nil {
			continue // drop invalid netpaths
		}

		paths = append(paths, np)
	}

	*n = paths
	return nil
}
