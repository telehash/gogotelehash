// Package transports implements Generic interfaces for telehash transports
//
// Transports must implement the Config and Transport interfaces. Endpoints
// are responsible for actually managing the transports.
//
//   e3x.New(keys, udp.Config{})
package transports

import (
	"errors"
)

// ErrClosed is returned by a transport when it is not open.
var ErrClosed = errors.New("use of closed network connection")

// ErrInvalidAddr is returned by a transport when the provided address cannot be
// handled by the transport.
var ErrInvalidAddr = errors.New("transports: invalid address")

// Config must be implemented by transport packages
type Config interface {
	Open() (Transport, error)
}

// Transport is an opened transport.
// This interface is used internally by E3X.
type Transport interface {

	// LocalAddresses returns all the known addresses this transport is reachable at.
	LocalAddresses() []Addr

	// ReadMessage is a blocking read on the transport.
	// When the transport is closed ErrClosed is returned.
	ReadMessage(p []byte) (n int, src Addr, err error)

	// WriteMessage is a blocking write on the transport.
	// When the transport is closed ErrClosed is returned.
	WriteMessage(p []byte, dst Addr) error

	// Close closes the transport.
	Close() error
}

// Addr represents an address.
type Addr interface {

	// Network returns the transport id. For example "udp4".
	Network() string

	// String returns a (somewhat) human readable representation of the address.
	String() string

	// MarshalJSON returns a JSON representation of the address.
	MarshalJSON() ([]byte, error)

	// Equal returns true if other is equal to this Addr.
	// Don't use this method directly instead use EqualAddr(a, b).
	Equal(other Addr) bool
}

// EqualAddr returns true if a and b are equal Addr.
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
