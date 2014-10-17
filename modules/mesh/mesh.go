package mesh

import (
	"errors"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

var ErrNotAuthorized = errors.New("link: not authorized")

type moduleKeyType string
type AcceptFunc func(addr *e3x.Addr, req, resp *lob.Packet) bool

const moduleKey = moduleKeyType("mesh")

func Register(e *e3x.Endpoint, accept AcceptFunc) {
	e.Use(moduleKey, newMesh(e, accept))
}

func FromEndpoint(e *e3x.Endpoint) Mesh {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}
	return mod.(*mesh)
}

type Mesh interface {
	Link(addr *e3x.Addr, pkt *lob.Packet) (Tag, error)
	HasLink(hashname.H) bool
}

type mesh struct {
	endpoint    *e3x.Endpoint
	accept      AcceptFunc
	cLink       chan *opLink
	cRelease    chan *opRelease
	cHasLink    chan opHasLink
	cEventIn    chan events.E
	cTerminate  chan struct{}
	links       map[hashname.H]*link
	last_tag_id uint64
}

type Tag struct {
	hashname hashname.H
	id       uint64
	mesh     *mesh
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

type opHasLink struct {
	hashname hashname.H
	resp     chan bool
}

func newMesh(e *e3x.Endpoint, accept AcceptFunc) *mesh {
	return &mesh{
		endpoint:   e,
		accept:     accept,
		cLink:      make(chan *opLink),
		cRelease:   make(chan *opRelease),
		cHasLink:   make(chan opHasLink),
		cEventIn:   make(chan events.E),
		cTerminate: make(chan struct{}),
		links:      make(map[hashname.H]*link),
	}
}

func (m *mesh) Init() error {
	m.endpoint.AddHandler("link", e3x.HandlerFunc(m.handle_link))
	m.endpoint.Subscribe(m.cEventIn)
	return nil
}

func (m *mesh) Start() error {
	go m.run()
	return nil
}

func (m *mesh) Stop() error {
	close(m.cTerminate)
	return nil
}

func (m *mesh) run() {
	for {
		select {

		case evt := <-m.cEventIn:
			m.handle_event(evt)

		case <-m.cTerminate:
			return

		case op := <-m.cLink:
			m.link(op)

		case op := <-m.cRelease:
			m.release(op)

		case op := <-m.cHasLink:
			m.has_link(op)

		}
	}
}

func (m *mesh) handle_event(x events.E) {
	switch evt := x.(type) {
	case *e3x.ExchangeClosedEvent:
		var (
			hn   = evt.Exchange.RemoteHashname()
			link = m.links[hn]
		)

		if link == nil {
			return
		}

		link.channel.Close()
		delete(m.links, hn)
	}
}

func (m *mesh) HasLink(h hashname.H) bool {
	op := opHasLink{h, make(chan bool)}
	m.cHasLink <- op
	return <-op.resp
}

func (m *mesh) has_link(op opHasLink) {
	l, f := m.links[op.hashname]
	op.resp <- f && len(l.tags) > 0 && l.channel != nil
}

func (m *mesh) Link(addr *e3x.Addr, pkt *lob.Packet) (Tag, error) {
	op := opLink{addr: addr, pkt: pkt, cErr: make(chan error)}
	m.cLink <- &op

	if err := <-op.cErr; err != nil {
		return Tag{}, err
	}

	return op.tag, nil
}

func (m *mesh) link(op *opLink) {
	l := m.links[op.addr.Hashname()]

	if l == nil {
		c, err := m.endpoint.Open(op.addr, "link", false)
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
		if m.accept != nil && !m.accept(op.addr, pkt, nil) {
			c.Errorf("access denied")
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

func (m *mesh) handle_link(ch *e3x.Channel) {
	pkt, err := ch.ReadPacket()
	if err != nil {
		ch.Close()
		return
	}

	resp := &lob.Packet{}

	if m.accept != nil && !m.accept(ch.RemoteAddr(), pkt, resp) {
		ch.Errorf("access denied")
		return
	}

	err = ch.WritePacket(resp)
	if err != nil {
		ch.Close()
		return
	}

	l := m.links[ch.RemoteHashname()]
	if l == nil {
		l = &link{
			addr: ch.RemoteAddr(),
			tags: make(map[uint64]bool),
		}
		m.links[ch.RemoteHashname()] = l
	}
	if l.channel != nil {
		l.channel.Close()
		l.channel = nil
	}
	l.channel = ch
}

func (t Tag) Release() {
	op := opRelease{tag: t}
	t.mesh.cRelease <- &op
}

func (m *mesh) release(op *opRelease) {
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
