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
	Open() (Transport, error)
}

type Transport interface {
	Run(w <-chan WriteOp, r chan<- ReadOp, e chan<- events.E) <-chan struct{}
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

type NetworkChangeEvent struct {
	Up   []Addr
	Down []Addr
}

func (e *NetworkChangeEvent) String() string {
	return fmt.Sprintf("network changed: up: %s down: %s", e.Up, e.Down)
}

type WriteOp struct {
	Msg []byte
	Dst Addr
	C   chan error
}

type ReadOp struct {
	Msg []byte
	Src Addr
}
