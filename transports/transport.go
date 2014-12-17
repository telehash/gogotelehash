// Package transports implements Generic interfaces for telehash transports
//
// Transports must implement the Config and Transport interfaces. Endpoints
// are responsible for actually managing the transports.
//
//   e3x.New(keys, udp.Config{})
package transports

import (
	"net"
)

// Config must be implemented by transport packages
type Config interface {
	Open() (Transport, error)
}

// Transport is an opened transport.
// This interface is used internally by E3X.
type Transport interface {

	// Addrs returns all the known addresses this transport is reachable at.
	Addrs() []net.Addr

	// Dial will open a new connection to addr.
	// io.EOF is returned when the transport is closed.
	// ErrInvalidAddr must be returned when the addr is
	// not suppoorted by the transport.
	Dial(addr net.Addr) (net.Conn, error)

	// Accept will accept the next incomming connection.
	// io.EOF is returned when the transport is closed.
	Accept() (c net.Conn, err error)

	// Close closes the transport.
	Close() error
}
