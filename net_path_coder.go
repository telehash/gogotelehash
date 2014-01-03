package telehash

import (
	"encoding/json"
	"fmt"
	"reflect"
)

var (
	np_name_to_type = map[string]reflect.Type{
		"ipv4":  reflect.TypeOf(IPv4NetPath{}),
		"ipv6":  reflect.TypeOf(IPv6NetPath{}),
		"relay": reflect.TypeOf(relay_net_path{}),
	}
	np_type_to_name = func() map[reflect.Type]string {
		m := map[reflect.Type]string{}
		for k, v := range np_name_to_type {
			m[v] = k
		}
		return m
	}()
)

func DecodeNetPath(data []byte) (NetPath, error) {
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

	np := reflect.New(t).Interface().(NetPath)

	err = json.Unmarshal(data, &np)
	if err != nil {
		return nil, err
	}

	return np, nil
}

func EncodeNetPath(n NetPath) ([]byte, error) {
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
