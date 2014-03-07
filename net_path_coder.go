package telehash

import (
	"encoding/json"
	"github.com/telehash/gogotelehash/net"
)

func init() {
	net.RegisterPathDecoder("relay", func(data []byte) (net.Addr, error) {
		addr := &relay_addr{}

		err := json.Unmarshal(data, &addr)
		if err != nil {
			return nil, err
		}

		return addr, nil
	})

	net.RegisterPathEncoder("relay", func(addr net.Addr) ([]byte, error) {
		return json.Marshal(addr.(*relay_addr))
	})
}
