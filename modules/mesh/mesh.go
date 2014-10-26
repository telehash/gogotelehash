package mesh

import (
	"errors"
	"sync"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
)

var ErrNotAuthorized = errors.New("link: not authorized")

type moduleKeyType string
type AcceptFunc func(ident *e3x.Ident, req, resp *lob.Packet) bool

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
	Link(ident *e3x.Ident, pkt *lob.Packet) (Tag, error)
	HasLink(hashname.H) bool
}

type mesh struct {
	endpoint    *e3x.Endpoint
	accept      AcceptFunc
	mtx         sync.Mutex
	links       map[hashname.H]*link
	last_tag_id uint64
}

type Tag struct {
	hashname hashname.H
	id       uint64
	mesh     *mesh
}

type link struct {
	ident   *e3x.Ident
	channel *e3x.Channel
	tags    map[uint64]bool
}

type opLink struct {
	ident *e3x.Ident
	pkt   *lob.Packet
	tag   Tag
	cErr  chan error
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
		endpoint: e,
		accept:   accept,
		links:    make(map[hashname.H]*link),
	}
}

func (m *mesh) Init() error {
	m.endpoint.AddHandler("link", e3x.HandlerFunc(m.handle_link))

	observers := e3x.ObserversFromEndpoint(m.endpoint)
	observers.Register(m.on_exchange_closed)
	return nil
}

func (m *mesh) Start() error { return nil }
func (m *mesh) Stop() error  { return nil }

func (m *mesh) on_exchange_closed(evt *e3x.ExchangeClosedEvent) {
	m.mtx.Lock()
	var (
		hn   = evt.Exchange.RemoteHashname()
		link = m.links[hn]
	)
	delete(m.links, hn)
	m.mtx.Unlock()

	if link != nil {
		link.channel.Close()
	}
}

func (m *mesh) HasLink(h hashname.H) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	l, f := m.links[h]
	return f && len(l.tags) > 0 && l.channel != nil
}

func (m *mesh) Link(addr *e3x.Ident, pkt *lob.Packet) (Tag, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := m.links[addr.Hashname()]

	if l == nil {
		c, err := m.endpoint.Open(addr, "link", false)
		if err != nil {
			return Tag{}, err
		}

		if pkt == nil {
			pkt = &lob.Packet{}
		}
		err = c.WritePacket(pkt)
		if err != nil {
			c.Close()
			return Tag{}, err
		}

		pkt, err := c.ReadPacket()
		if err != nil {
			c.Close()
			return Tag{}, err
		}

		// authenticate peer
		if m.accept != nil && !m.accept(addr, pkt, nil) {
			c.Errorf("access denied")
			return Tag{}, ErrNotAuthorized
		}

		l = &link{addr, c, make(map[uint64]bool)}
		m.links[addr.Hashname()] = l
	}

	m.last_tag_id++
	t := Tag{addr.Hashname(), m.last_tag_id, m}
	l.tags[m.last_tag_id] = true

	return t, nil
}

func (m *mesh) handle_link(ch *e3x.Channel) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	pkt, err := ch.ReadPacket()
	if err != nil {
		ch.Close()
		return
	}

	resp := &lob.Packet{}

	if m.accept != nil && !m.accept(ch.RemoteIdent(), pkt, resp) {
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
			ident: ch.RemoteIdent(),
			tags:  make(map[uint64]bool),
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
	m := t.mesh

	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := m.links[t.hashname]
	if l == nil {
		return
	}

	if !l.tags[t.id] {
		return
	}

	delete(l.tags, t.id)

	if len(l.tags) == 0 {
		l.channel.Close()
		delete(m.links, t.hashname)
	}
}
