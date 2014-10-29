// Package inproc implements the in-process transport
package inproc

import (
	"encoding/json"
	"sync"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/bufpool"
)

// Config for the inproc transport. There are no configuration options for now.
//
//   e3x.New(keys, inproc.Config{})
type Config struct {
}

type addr struct {
	id uint32
}

type transport struct {
	id uint32
	c  chan packet
}

type packet struct {
	from uint32
	buf  []byte
}

var (
	_ transports.Addr      = (*addr)(nil)
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

var (
	mtx    sync.RWMutex
	pipes  = map[uint32]*transport{}
	netxId uint32
)

// Open opens the transport.
func (c Config) Open() (transports.Transport, error) {
	mtx.Lock()
	id := netxId
	t := &transport{id, make(chan packet, 10)}
	netxId++
	pipes[id] = t
	mtx.Unlock()

	return t, nil
}

func (t *transport) ReadMessage(p []byte) (int, transports.Addr, error) {
	pkt, open := <-t.c
	if !open {
		return 0, nil, transports.ErrClosed
	}

	n := len(pkt.buf)
	copy(p, pkt.buf)
	bufpool.PutBuffer(pkt.buf)

	return n, &addr{pkt.from}, nil
}

func (t *transport) WriteMessage(p []byte, dst transports.Addr) error {
	a, ok := dst.(*addr)
	if !ok || a == nil {
		return transports.ErrInvalidAddr
	}

	mtx.RLock()
	dstT := pipes[a.id]
	mtx.RUnlock()

	if dstT == nil {
		return nil // drop
	}

	buf := bufpool.GetBuffer()
	copy(buf, p)
	buf = buf[:len(p)]

	func() {
		defer func() { recover() }()
		dstT.c <- packet{t.id, buf}
	}()

	return nil
}

func (t *transport) LocalAddresses() []transports.Addr {
	return []transports.Addr{
		&addr{t.id},
	}
}

func (t *transport) Close() error {
	mtx.Lock()
	delete(pipes, t.id)
	mtx.Unlock()

	close(t.c)
	return nil
}

func (a *addr) Network() string {
	return "inproc"
}

func (a *addr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}{
		Type: "inproc",
		ID:   int(a.id),
	}
	return json.Marshal(&desc)
}

func (a *addr) Equal(x transports.Addr) bool {
	b := x.(*addr)

	if a.id != b.id {
		return false
	}

	return true
}

func (a *addr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
}
