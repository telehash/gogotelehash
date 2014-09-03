package transports

import (
	"errors"
	"sync"
)

var ErrClosed = errors.New("use of closed network connection")
var ErrInvalidAddr = errors.New("transports: invalid address")

type Config interface {
	Open() (Transport, error)
}

type Transport interface {
	Close() error

	CanHandleAddress(addr Addr) bool
	DecodeAddress(data []byte) (Addr, error)
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

const bufferSize = 64 * 1024

var zeroBuffer = make([]byte, bufferSize)

var bufferPool = sync.Pool{
	New: func() interface{} { return make([]byte, bufferSize) },
}

func GetBuffer() []byte {
	buf := bufferPool.Get().([]byte)
	return buf[:bufferSize]
}

func PutBuffer(buf []byte) {
	if cap(buf) != bufferSize {
		panic("invalid buffer return")
	}

	buf = buf[:bufferSize]
	copy(buf, zeroBuffer)

	bufferPool.Put(buf)
}
