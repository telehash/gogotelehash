package transports

import (
	"errors"
)

var ErrClosed = errors.New("use of closed network connection")
var ErrInvalidAddr = errors.New("transports: invalid address")

type Config interface {
	Open() (Transport, error)
}

type Transport interface {
	LocalAddresses() []Addr
	ReadMessage(p []byte) (n int, src Addr, err error)
	WriteMessage(p []byte, dst Addr) error
	Close() error
}

type Addr interface {
	Network() string
	String() string
	MarshalJSON() ([]byte, error)
	Equal(Addr) bool
}

func EqualAddr(a, b Addr) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Network() != b.Network() {
		return false
	}
	return a.Equal(b)
}
