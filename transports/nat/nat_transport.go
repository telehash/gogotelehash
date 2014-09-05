package nat

import (
	"bytes"
	"net"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/nat"
)

var (
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

type NATableAddr interface {
	InternalAddr() (proto string, ip net.IP, port int)
	MakeGlobal(ip net.IP, port int) transports.Addr
}

type Config struct {
	Config transports.Config
}

type transport struct {
	mtx         sync.Mutex
	t           transports.Transport
	mappedAddrs []transports.Addr
	nat         nat.NAT
	ticker      *time.Ticker
}

func (c Config) Open() (transports.Transport, error) {
	t, err := c.Config.Open()
	if err != nil {
		return nil, err
	}

	nt := &transport{t: t}
	go nt.run()

	return nt, nil
}

func (t *transport) Close() error {
	t.ticker.Stop()
	return t.t.Close()
}

func (t *transport) CanHandleAddress(addr transports.Addr) bool {
	return t.t.CanHandleAddress(addr)
}

func (t *transport) LocalAddresses() []transports.Addr {
	t.mtx.Lock()
	m := t.mappedAddrs
	t.mtx.Unlock()

	return append(m, t.t.LocalAddresses()...)
}

func (t *transport) Deliver(pkt []byte, to transports.Addr) error {
	return t.t.Deliver(pkt, to)
}

func (t *transport) Receive(b []byte) (int, transports.Addr, error) {
	return t.t.Receive(b)
}

func (t *transport) run() {
	t.ticker = time.NewTicker(30 * time.Second)

	m := t.refresh()
	t.mtx.Lock()
	t.mappedAddrs = m
	t.mtx.Unlock()

	for _ = range t.ticker.C {
		m := t.refresh()
		t.mtx.Lock()
		t.mappedAddrs = m
		t.mtx.Unlock()
	}
}

func (t *transport) refresh() []transports.Addr {
	var (
		mappedAddrs []transports.Addr
	)

	if t.nat == nil {
		n, err := nat.Discover()
		if err != nil {
			tracef("NAT: no gateway was found. (%s)", err)
			return nil
		}
		t.nat = n
	}

	external_ip, err := t.nat.GetExternalAddress()
	if err != nil {
		tracef("NAT: gateway is broken (%s)", err)
		t.nat = nil
		return nil
	}

	internal_ip, err := t.nat.GetInternalAddress()
	if err != nil {
		tracef("NAT: gateway is broken (%s)", err)
		t.nat = nil
		return nil
	}

	for _, addr := range t.t.LocalAddresses() {
		nataddr, ok := addr.(NATableAddr)
		if !ok {
			continue
		}

		proto, ip, internal_port := nataddr.InternalAddr()
		if proto == "" || ip == nil || internal_port <= 0 {
			continue
		}

		if !bytes.Equal(ip, internal_ip) {
			continue
		}

		external_port, err := t.nat.AddPortMapping(proto, internal_port, "Telehash", 60*time.Second)
		if err != nil {
			tracef("NAT: failed to map %s %d", internal_ip, internal_port)
			continue
		}

		globaddr := nataddr.MakeGlobal(external_ip, external_port)
		if globaddr == nil {
			tracef("NAT: failed to map %s %d", internal_ip, internal_port)
			t.nat.DeletePortMapping(proto, internal_port)
			continue
		}

		tracef("NAT: mapped %s to %s", addr, globaddr)
		mappedAddrs = append(mappedAddrs, globaddr)
	}

	if len(mappedAddrs) == 0 {
		tracef("NAT: no mappable addresses")
	}

	return mappedAddrs
}
