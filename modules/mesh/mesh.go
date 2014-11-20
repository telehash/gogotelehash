package mesh

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/hashname"
	"github.com/telehash/gogotelehash/lob"
	"github.com/telehash/gogotelehash/util/logs"
)

var ErrNotAuthorized = errors.New("link: not authorized")

type moduleKeyType string
type AcceptFunc func(ident *e3x.Identity, req, resp *lob.Packet) bool

const moduleKey = moduleKeyType("mesh")

func Module(accept AcceptFunc) func(*e3x.Endpoint) error {
	return func(e *e3x.Endpoint) error {
		return e3x.RegisterModule(moduleKey, newMesh(e, accept))(e)
	}
}

func FromEndpoint(e *e3x.Endpoint) Mesh {
	mod := e.Module(moduleKey)
	if mod == nil {
		return nil
	}
	return mod.(*mesh)
}

type Mesh interface {
	Link(ident *e3x.Identity, pkt *lob.Packet) (Tag, error)
	HasLink(hashname.H) bool
	Exchange(hashname.H) *e3x.Exchange
	LinkedExchanges() []*e3x.Exchange
}

type mesh struct {
	endpoint     *e3x.Endpoint
	accept       AcceptFunc
	mtx          sync.Mutex
	observers    e3x.Observers
	linkListener *e3x.Listener
	links        map[hashname.H]*link
	last_tag_id  uint64
}

type Tag struct {
	hashname hashname.H
	id       uint64
	mesh     *mesh
}

type link struct {
	ident    *e3x.Identity
	exchange *e3x.Exchange
	channel  *e3x.Channel
	tags     map[uint64]bool
}

type opLink struct {
	ident *e3x.Identity
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
	m.observers = e3x.ObserversFromEndpoint(m.endpoint)
	m.observers.Register(m.onExchangeClosed)
	return nil
}

func (m *mesh) Start() error {
	m.linkListener = m.endpoint.Listen("link", true)

	go m.accept_links()

	return nil
}

func (m *mesh) Stop() error {
	if m.linkListener != nil {
		m.linkListener.Close()
		m.linkListener = nil
	}

	return nil
}

func (m *mesh) onExchangeClosed(evt *e3x.ExchangeClosedEvent) {
	m.unlink(evt.Exchange.RemoteHashname())
}

func (m *mesh) unlink(hn hashname.H) {
	m.mtx.Lock()
	link := m.links[hn]
	delete(m.links, hn)
	m.mtx.Unlock()

	if link != nil {
		link.channel.Close()
		logs.From(m.endpoint.LocalHashname()).To(hn).Module("mesh").Println("Unlinked")
		m.observers.Trigger(&LinkDownEvent{link.exchange})
	}
}

func (m *mesh) HasLink(h hashname.H) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	l, f := m.links[h]
	return f && l.channel != nil
}

func (m *mesh) Exchange(h hashname.H) *e3x.Exchange {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	l, f := m.links[h]
	if !f || l == nil {
		return nil
	}

	return l.exchange
}

func (m *mesh) LinkedExchanges() []*e3x.Exchange {
	m.mtx.Lock()
	exchanges := make([]*e3x.Exchange, 0, len(m.links))
	for _, link := range m.links {
		exchanges = append(exchanges, link.exchange)
	}
	m.mtx.Unlock()

	return exchanges
}

func (m *mesh) Link(ident *e3x.Identity, pkt *lob.Packet) (Tag, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := m.links[ident.Hashname()]

	if l == nil {
		x, err := m.endpoint.Dial(ident)
		if err != nil {
			return Tag{}, err
		}

		c, err := x.Open("link", true)
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
		if m.accept != nil && !m.accept(ident, pkt, nil) {
			c.Errorf("access denied")
			return Tag{}, ErrNotAuthorized
		}

		go m.keepChannelOpen(c)

		l = &link{ident, x, c, make(map[uint64]bool)}
		m.links[ident.Hashname()] = l

		logs.From(m.endpoint.LocalHashname()).To(ident.Hashname()).Module("mesh").Println("Linked")
		m.observers.Trigger(&LinkUpEvent{l.exchange})
	}

	m.last_tag_id++
	t := Tag{ident.Hashname(), m.last_tag_id, m}
	l.tags[m.last_tag_id] = true

	return t, nil
}

func (m *mesh) accept_links() {
	for {
		c, err := m.linkListener.AcceptChannel()
		if err == io.EOF {
			return
		}
		if err != nil {
			continue
		}

		go m.handle_link(c)
	}
}

func (m *mesh) handle_link(ch *e3x.Channel) {
	pkt, err := ch.ReadPacket()
	if err != nil {
		ch.Close()
		return
	}

	resp := &lob.Packet{}

	if m.accept != nil && !m.accept(ch.RemoteIdentity(), pkt, resp) {
		ch.Errorf("access denied")
		return
	}

	err = ch.WritePacket(resp)
	if err != nil {
		ch.Close()
		return
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	l := m.links[ch.RemoteHashname()]
	if l == nil {
		l = &link{
			exchange: ch.Exchange(),
			ident:    ch.RemoteIdentity(),
			tags:     make(map[uint64]bool),
		}
		m.links[ch.RemoteHashname()] = l
	}
	if l.channel != nil {
		l.channel.Close()
		l.channel = nil
	}
	l.channel = ch

	logs.From(m.endpoint.LocalHashname()).To(ch.RemoteHashname()).Module("mesh").Println("Linked")
	m.observers.Trigger(&LinkUpEvent{l.exchange})

	go m.keepChannelOpen(ch)
}

func (t Tag) Release() {
	var (
		m = t.mesh
		c *e3x.Channel
	)

	if m == nil {
		return
	}

	m.mtx.Lock()
	l := m.links[t.hashname]
	if l != nil {
		if l.tags[t.id] {
			delete(l.tags, t.id)
		}
		if len(l.tags) == 0 {
			delete(m.links, t.hashname)
			c = l.channel
		}
	}
	m.mtx.Unlock()

	if c != nil {
		c.Close()
	}
}

func (m *mesh) keepChannelOpen(c *e3x.Channel) {
	defer m.unlink(c.RemoteHashname())

	for {
		_, err := c.ReadPacket()
		if err != nil {
			return
		}
	}
}

type LinkUpEvent struct {
	Exchange *e3x.Exchange
}

type LinkDownEvent struct {
	Exchange *e3x.Exchange
}

func (event *LinkUpEvent) String() string {
	return fmt.Sprintf("Mesh Link up %s", event.Exchange.RemoteHashname())
}

func (event *LinkDownEvent) String() string {
	return fmt.Sprintf("Mesh Link down %s", event.Exchange.RemoteHashname())
}
