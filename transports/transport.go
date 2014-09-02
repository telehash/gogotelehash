package transports

import (
	"errors"
)

var ErrTransportClosed = errors.New("transports: transport is closed")
var ErrInvalidAddr = errors.New("transports: invalid address")

type Factory interface {
	Open() (Transport, error)
}

type Transport interface {
	Networks() []string
	Close() error

	DecodeAddress(data []byte) (ResolvedAddr, error)
	LocalAddresses() []ResolvedAddr
	DefaultMTU() int

	Deliver(pkt []byte, to ResolvedAddr) error
	Receive(b []byte) (int, ResolvedAddr, error)
}

type Addr interface {
	String() string
}

type ResolvedAddr interface {
	Addr
	Network() string
	MarshalJSON() ([]byte, error)
	Less(ResolvedAddr) bool
}

type UnresolverAddr interface {
	Addr
	Resolve(*Manager) []ResolvedAddr
}
