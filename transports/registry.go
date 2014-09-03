package transports

import (
	"encoding/json"
)

var addressDecoders = map[string]AddrDecoder{}

type AddrDecoder func([]byte) (Addr, error)

func RegisterAddrDecoder(typ string, d AddrDecoder) {
	addressDecoders[typ] = d
}

func DecodeAddr(p []byte) (Addr, error) {
	var desc struct {
		Type string `json:"type"`
	}

	err := json.Unmarshal(p, &desc)
	if err != nil {
		return nil, ErrInvalidAddr
	}

	d := addressDecoders[desc.Type]
	if d == nil {
		return nil, ErrInvalidAddr
	}

	return d(p)
}
