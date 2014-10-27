package transports

import (
	"encoding/json"
)

var addressDecoders = map[string]AddrDecoder{}

type AddrDecoder func([]byte) (Addr, error)

// RegisterAddrDecoder registers an AddrDecoder
// Addr types that are expected to be communicated through telehash must be
// registered here.
func RegisterAddrDecoder(typ string, d AddrDecoder) {
	addressDecoders[typ] = d
}

// DecodeAddr will decode an address from JSON using the appropriate AddrDecoder.
// ErrInvalidAddr is returned when the address could not be decoded.
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
