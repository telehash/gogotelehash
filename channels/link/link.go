package link

import (
	"errors"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var ErrNotAuthorized = errors.New("link: not authorized")

type Mesh struct {
	Endpoint *e3x.Endpoint
	Accept   func(addr *e3x.Addr, pkt *lob.Packet) bool

	subscribers events.Hub
	cLink       chan *opLink
	cRelease    chan *opRelease
	cTerminate  chan struct{}
	links       map[hashname.H]*link
	last_tag_id uint64
}

type Tag struct {
	hashname hashname.H
	id       uint64
	mesh     *Mesh
}

type link struct {
	addr    *e3x.Addr
	channel *e3x.Channel
	tags    map[uint64]bool
}

type opLink struct {
	addr *e3x.Addr
	pkt  *lob.Packet
	tag  Tag
	cErr chan error
}

type opRelease struct {
	tag Tag
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

		case op := <-m.cLink:
			m.link(op)

		case op := <-m.cRelease:
			m.release(op)

		}
	}
}

func (m *Mesh) handle_event(x events.E) {
	switch evt := x.(type) {
	case *e3x.ExchangeClosedEvent:
		// unlink evt.Hashname
	}
}

func (m *Mesh) Link(addr *e3x.Addr, pkt *lob.Packet) (Tag, error) {
	op := opLink{addr: addr, pkt: pkt, cErr: make(chan error)}
	m.cLink <- &op

	if err := <-op.cErr; err != nil {
		return Tag{}, err
	}

	return op.tag, nil
}

func (m *Mesh) link(op *opLink) {
	l := m.links[op.addr.Hashname()]

	if l == nil {
		c, err := m.Endpoint.Dial(op.addr, "link", false)
		if err != nil {
			op.cErr <- err
			return
		}

		if op.pkt == nil {
			op.pkt = &lob.Packet{}
		}
		err = c.WritePacket(op.pkt)
		if err != nil {
			c.Close()
			op.cErr <- err
			return
		}

		pkt, err := c.ReadPacket()
		if err != nil {
			c.Close()
			op.cErr <- err
			return
		}

		// authenticate peer
		if m.Accept != nil && !m.Accept(op.addr, pkt) {
			c.Close()
			op.cErr <- ErrNotAuthorized
			return
		}

		l = &link{op.addr, c, make(map[uint64]bool)}
		m.links[op.addr.Hashname()] = l
	}

	m.last_tag_id++
	t := Tag{op.addr.Hashname(), m.last_tag_id, m}
	l.tags[m.last_tag_id] = true

	op.tag = t
	op.cErr <- nil
	return
}

func (t Tag) Release() {
	op := opRelease{tag: t}
	t.mesh.cRelease <- &op
}

func (m *Mesh) release(op *opRelease) {
	l := m.links[op.tag.hashname]
	if l == nil {
		return
	}

	if !l.tags[op.tag.id] {
		return
	}

	delete(l.tags, op.tag.id)

	if len(l.tags) == 0 {
		l.channel.Close()
		delete(m.links, op.tag.hashname)
	}
}

func (m *Mesh) Subscribe(c chan<- events.E) {
	m.subscribers.Subscribe(c)
}

func (m *Mesh) Unubscribe(c chan<- events.E) {
	m.subscribers.Unubscribe(c)
}
