package transports

import (
	"bitbucket.org/simonmenke/go-telehash/lob"
)

type Manager struct{}

func (m *Manager) Deliver(pkt *lob.Packet, addr Addr) error { panic("TODO") }
func (m *Manager) Receive() (*lob.Packet, Addr)             { panic("TODO") }

type Transport interface {
	Open() error
	Close() error

	LocalAddresses() []transports.Addr
	DefaultMTU() int

	Deliver(pkt []byte, to Addr) error
	Receive(b []byte) (int, Addr, error)
}

type Addr interface {
	Network() string
	MarshalJSON() ([]byte, error)
	Less(Addr) bool
	String() string
}
