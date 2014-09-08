package link

import (
	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

type Mesh struct {
	Endpoint *e3x.Endpoint
	Accept   func(addr *e3x.Addr, pkt *lob.Packet) bool

	links       map[hashname.H]*link
	subscribers events.Hub
}

type link struct {
	addr    *e3x.Addr
	channel *e3x.Channel
}

func (m *Mesh) run() {
	in := make(chan events.E)
	m.Endpoint.Subscribe(in)
	defer m.Endpoint.Unsubscribe(in)

	for {
		select {

		case evt := <-in:
			m.handle_event(evt)

		case <-m.cTerminate:
			return

		}
	}
}

func (m *Mesh) handle_event(x events.E) {
	switch evt := x.(type) {
	case *e3x.ExchangeClosedEvent:
		// unlink evt.Hashname
	}
}

func (m *Mesh) Link(addr *e3x.Addr, pkt *lob.Packet) error {

}

func (m *Mesh) Unlink(hashname hashname.H) {

}

func (m *Mesh) Links() []*e3x.Addr {

}

func (m *Mesh) Subscribe(c chan<- event.E) {
	m.subscribers.Subscribe(c)
}

func (m *Mesh) Unubscribe(c chan<- event.E) {
	m.subscribers.Unubscribe(c)
}
