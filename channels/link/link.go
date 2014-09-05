package link

import (
  "bitbucket.org/simonmenke/go-telehash/e3x"
  "bitbucket.org/simonmenke/go-telehash/hashname"
  "bitbucket.org/simonmenke/go-telehash/lob"
)

type Mesh struct {
  Endpoint *e3x.Endpoint
  Accept   func(addr *e3x.Addr, pkt *lob.Packet) bool

  links map[hashname.H]*link
}

type link struct {
  addr    *e3x.Addr
  channel *e3x.Channel
}

func (m *Mesh) Link(addr *e3x.Addr, pkt *lob.Packet) (*link, error) {

}

func (m *Mesh) Unlink(hashname hashname.H) {

}

func (m *Mesh) Links() []*e3x.Addr {

}

func (m *Mesh) Observe(c chan<- event.E) event.Observer {

}
