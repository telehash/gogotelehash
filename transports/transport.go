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

type AddrSet []Addr

func (a *AddrSet) Add(addr Addr) (added bool) {
	if a.Index(addr) < 0 {
		*a = append(*a, addr)
		return true
	}
	return false
}

func (a *AddrSet) Remove(addr Addr) (removed bool) {
	if idx := a.Index(addr); idx >= 0 {
		s := *a
		l := len(s)
		if idx < l-1 {
			copy(s[idx:], s[idx+1:])
		}
		*a = s[:l-1]
		return true
	}
	return false
}

func (a *AddrSet) Index(addr Addr) int {
	s := *a
	for i, a := range s {
		if EqualAddr(a, addr) {
			return i
		}
	}
	return -1
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
