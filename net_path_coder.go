package telehash

import (
	"encoding/json"
	"fmt"
	"reflect"
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

	t, ok := np_name_to_type[typ.Type]
	if !ok {
		return nil, fmt.Errorf("Unknown type %q", typ.Type)
	}

	np := reflect.New(t).Interface().(net_path)

	err = json.Unmarshal(data, &np)
	if err != nil {
		return nil, err
	}

	return np, nil
}

func (s *Switch) encode_net_path(n *net_path) ([]byte, error) {
	t := reflect.TypeOf(n)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	name, ok := np_type_to_name[t]
	if !ok {
		return nil, fmt.Errorf("Unknown type %T", n)
	}

	data, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	data2 := make([]byte, len(data)+len(name)+10)
	data2[0] = data[0]
	copy(data2[1:], "\"type\":\"")
	copy(data2[9:], name)
	copy(data2[len(name)+9:], "\",")
	copy(data2[len(name)+11:], data[1:])

	return data2, nil
}
