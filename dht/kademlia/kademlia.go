package kademlia

import (
	"bitbucket.org/simonmenke/go-telehash/hashname"
	"bitbucket.org/simonmenke/go-telehash/lob"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/e3x"
	"bitbucket.org/simonmenke/go-telehash/modules/mesh"
)

type moduleKey string

func Register(e *e3x.Endpoint, key string) {
	e.Use(moduleKey(key), newDHT(e))
}

func FromEndpoint(e *e3x.Endpoint, key string) DHT {
	mod := e.Module(moduleKey(key))
	if mod == nil {
		return nil
	}
	return mod.(*dht)
}

type DHT interface {
	Lookup(key []byte) (*e3x.Addr, error)
	Resolve(hn hashname.H) (*e3x.Addr, error)
}

type dht struct {
	mtx        sync.Mutex
	prefix     string
	e          *e3x.Endpoint
	m          mesh.Mesh
	cTerminate chan struct{}
	table      [][]*link
}

type link struct {
	tag mesh.Tag
}

func newDHT(e *e3x.Endpoint, key string) *dht {
	prefix := ""
	if key != "" {
		prefix = key + "/"
	}

	return &dht{
		e:          e,
		prefix:     prefix,
		cTerminate: make(chan struct{}),
	}
}

func (d *dht) Init() error {
	d.m = mesh.FromEndpoint(d.e)
	if d.m == nil {
		panic("kademlia requires the mesh module.")
	}

	d.e.AddHandler(d.prefix+"see", e3x.HandlerFunc(d.handle_see))

	return nil
}

func (d *dht) Start() error {
	go d.run()
	return nil
}

func (d *dht) Stop() error {
	close(d.cTerminate)
	return nil
}

func (d *dht) Lookup(key []byte) (*e3x.Addr, error) {

}

func (d *dht) run() {
	var (
		refresh = time.NewTicker(1 * time.Minute)
	)

	defer refresh.Stop()

	for {
		select {
		case <-d.cTerminate:
			return

		case <-refresh.C:
			go d.refresh()

		}
	}
}

func (d *dht) refresh() {
	self, err := d.e.LocalAddr()
	if err != nil {
		return
	}

}

func (d *dht) see(key string, x *e3x.Exchange) ([]hashname.H, error) {
	c, err := x.Open(d.prefix+"see", false)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	pkt := &lob.Packet{}
	pkt.Header().SetString("key", key)
	pkt.Header().SetBool("end", true)
	err = c.WritePacket(pkt)
	if err != nil {
		return nil, err
	}

	pkt, err = c.ReadPacket()
	if err != nil {
		return nil, err
	}

	v, _ := pkt.Header().Get("see")
	l, ok := v.([]string)
	if !ok {
		return nil, nil
	}

	h := make([]hashname.H, len(l))
	for i, s := range l {
		h[i] = hashname.H(s)
	}

	return h, nil
}

func (d *dht) handle_see(c *e3x.Channel) {
	defer c.Close()

	pkt, err := c.ReadPacket()
	if err != nil {
		return
	}

	key, ok := pkt.Header().GetString("key")
	if !ok {
		return
	}

	h := d.localLookup(key)

	pkt = &lob.Packet{}
	pkt.Header().Set("see", h)
	pkt.Header().SetBool("end", true)
	err = c.WritePacket(pkt)
	if err != nil {
		return
	}
}
