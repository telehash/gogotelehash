// Package inproc implements the in-process transport
package inproc

import (
	"encoding/json"
	"io"
	"net"
	"sync"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/dgram"
	"github.com/telehash/gogotelehash/util/bufpool"
)

func init() {
	transports.RegisterAddr(&inprocAddr{})
}

// Config for the inproc transport. There are no configuration options for now.
//
//   e3x.New(keys, inproc.Config{})
type Config struct {
}

type inprocAddr struct {
	id uint32
}

type transport struct {
	laddr *inprocAddr
	c     chan packet
}

type packet struct {
	from *inprocAddr
	buf  []byte
}

var (
	_ dgram.Addr        = (*inprocAddr)(nil)
	_ dgram.Transport   = (*transport)(nil)
	_ transports.Config = Config{}
)

var (
	mtx    sync.RWMutex
	pipes  = map[uint32]*transport{}
	netxID uint32
)

// Open opens the transport.
func (c Config) Open() (transports.Transport, error) {
	mtx.Lock()
	id := netxID
	t := &transport{&inprocAddr{id}, make(chan packet, 10)}
	netxID++
	pipes[id] = t
	mtx.Unlock()

	return dgram.Wrap(t)
}

func (t *transport) NormalizeAddr(addr net.Addr) (dgram.Addr, error) {
	if a, ok := addr.(*inprocAddr); ok {
		return a, nil
	} else {
		return nil, transports.ErrInvalidAddr
	}
}

func (t *transport) Read(p []byte) (int, dgram.Addr, error) {
	pkt, open := <-t.c
	if !open {
		return 0, nil, io.EOF
	}

	n := len(pkt.buf)
	copy(p, pkt.buf)
	bufpool.PutBuffer(pkt.buf)

	return n, pkt.from, nil
}

func (t *transport) Write(p []byte, dst dgram.Addr) (int, error) {
	a, ok := dst.(*inprocAddr)
	if !ok || a == nil {
		return 0, transports.ErrInvalidAddr
	}

	mtx.RLock()
	dstT := pipes[a.id]
	mtx.RUnlock()

	if dstT == nil {
		return 0, nil // drop
	}

	buf := bufpool.GetBuffer()
	copy(buf, p)
	buf = buf[:len(p)]

	func() {
		defer func() { recover() }()
		dstT.c <- packet{t.laddr, buf}
	}()

	return len(p), nil
}

func (t *transport) Addrs() []net.Addr {
	return []net.Addr{t.laddr}
}

func (t *transport) Close() error {
	mtx.Lock()
	delete(pipes, t.laddr.id)
	mtx.Unlock()

	close(t.c)
	return nil
}

func (a *inprocAddr) Network() string {
	return "inproc"
}

func (a *inprocAddr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
}

func (a *inprocAddr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}{
		Type: "inproc",
		ID:   int(a.id),
	}
	return json.Marshal(&desc)
}

func (a *inprocAddr) UnmarshalJSON(data []byte) error {
	var desc struct {
		Type string `json:"type"`
		ID   int    `json:"id"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return err
	}

	if desc.ID < 0 {
		return transports.ErrInvalidAddr
	}

	a.id = uint32(desc.ID)
	return nil
}

func (a *inprocAddr) Key() interface{} {
	return a.id
}
