package transports

import (
  "errors"
)

var ErrTransportClosed = errors.New("transports: transport is closed")

type Transport interface {
  Open() error
  Close() error

  CanDeliverTo(addr ResolvedAddr) bool
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
