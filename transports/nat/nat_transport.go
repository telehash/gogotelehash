package nat

import (
	"bytes"
	"net"
	"sync"
	"time"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/events"
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
	wg          sync.WaitGroup
	mtx         sync.Mutex
	t           transports.Transport
	mappedAddrs []transports.Addr
	nat         nat.NAT
	cEventIn    chan events.E
	cEventOut   chan<- events.E
	cTerminate  chan struct{}
	err         error
}

func (c Config) Open(e chan<- events.E) (transports.Transport, error) {
	nt := &transport{
		cEventIn:   make(chan events.E),
		cEventOut:  e,
		cTerminate: make(chan struct{}),
	}

	t, err := c.Config.Open(nt.cEventIn)
	if err != nil {
		return nil, err
	}

	nt.t = t
	nt.mappedAddrs = nt.refresh()
	nt.wg.Add(1)
	go nt.run()

	return nt, nil
}

func (t *transport) Close() error {
	detectClosed(func() { t.cTerminate <- struct{}{} })
	t.wg.Wait()
	return t.err
}

func (t *transport) close() {
	t.err = t.t.Close()
	close(t.cEventIn)
	close(t.cTerminate)
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

	var (
		ticker    = time.NewTicker(30 * time.Second)
		currEvent events.E
	)

	defer t.wg.Done()
	defer ticker.Stop()

	for {
		var (
			cEventIn  = t.cEventIn
			cEventOut = t.cEventOut
		)

		if currEvent == nil {
			cEventOut = nil
		} else {
			cEventIn = nil
		}

		select {

		case <-t.cTerminate:
			t.close()
			return

		case evt := <-cEventIn:
			currEvent = evt
		case cEventOut <- currEvent:
			currEvent = nil

		case <-ticker.C:
			m := t.refresh()
			t.mtx.Lock()
			t.mappedAddrs = m
			t.mtx.Unlock()

		}
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

	gateway_ip, err := t.nat.GetDeviceAddress()
	if err != nil {
		tracef("NAT: gateway is broken (%s)", err)
		t.nat = nil
		return nil
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

	internal_ip = internal_ip.To16()
	tracef("NAT: Using gateway %s (internal=%s external=%s)", gateway_ip, internal_ip, external_ip)

	for _, addr := range t.t.LocalAddresses() {
		nataddr, ok := addr.(NATableAddr)
		if !ok {
			tracef("NAT: not a nat address: %s", addr)
			continue
		}

		proto, ip, internal_port := nataddr.InternalAddr()
		if proto == "" || ip == nil || internal_port <= 0 {
			tracef("NAT: not a nat address: %s", addr)
			continue
		}

		if !bytes.Equal(ip.To16(), internal_ip) {
			tracef("NAT: not a nat address: %s (internal=%s)", ip, internal_ip)
			continue
		}

		tracef("NAT: mapping %s", addr)
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

func detectClosed(f func()) (closed bool) {
	defer func() { closed = recover() != nil }()
	f()
	return false
}
