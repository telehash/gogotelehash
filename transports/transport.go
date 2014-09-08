package transports

import (
	"errors"
	"fmt"

	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var ErrClosed = errors.New("use of closed network connection")
var ErrInvalidAddr = errors.New("transports: invalid address")

var (
	_ events.E = (*NetworkChangeEvent)(nil)
)

type Config interface {
	Open(e chan<- events.E) (Transport, error)
}

type Transport interface {
	Close() error

	CanHandleAddress(addr Addr) bool
	LocalAddresses() []Addr

	Deliver(pkt []byte, to Addr) error
	Receive(b []byte) (int, Addr, error)
}

type Addr interface {
	Network() string
	String() string
	MarshalJSON() ([]byte, error)
	Less(Addr) bool
}

type NetworkChangeEvent struct {
	Up   []Addr
	Down []Addr
}

func (e *NetworkChangeEvent) String() string {
	return fmt.Sprintf("network changed: up: %s down: %s", e.Up, e.Down)
}
