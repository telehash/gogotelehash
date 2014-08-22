package transports

type Transport interface {
  CanDeliverTo(path Path) bool
  Deliver(pkt []byte, to Path) error
  Receive() ([]byte, Path, error)

  Close() error
}

type Path interface{}
