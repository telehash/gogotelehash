package nat

import (
	"fmt"
	"net"
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
	transports.Addr
	InternalAddr() (proto string, ip net.IP, port int)
	MakeGlobal(ip net.IP, port int) transports.Addr
}

type Config struct {
	Config transports.Config
}

type transport struct {
	t       transports.Transport
	nat     nat.NAT
	mapping map[string]transports.Addr
}

func (c Config) Open() (transports.Transport, error) {
	t, err := c.Config.Open()
	if err != nil {
		return nil, err
	}

	return &transport{t: t, mapping: make(map[string]transports.Addr)}, nil
}

func (t *transport) Run(w <-chan transports.WriteOp, r chan<- transports.ReadOp, out chan<- events.E) <-chan struct{} {
	var (
		in   = make(chan events.E)
		done = t.t.Run(w, r, in)
	)

	go t.run_mapper(done, in, out)

	return done
}

func (t *transport) run_mapper(done <-chan struct{}, in <-chan events.E, out chan<- events.E) {
	var (
		closed bool
	)

	for !closed {
		if t.nat == nil {
			closed = t.run_discover_mode(done, in, out)
		} else {
			closed = t.run_mapping_mode(done, in, out)
		}
	}
}

func (t *transport) run_discover_mode(done <-chan struct{}, in <-chan events.E, out chan<- events.E) bool {
	var ticker = time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {

		case _, closed := <-done:
			if closed {
				return true // done
			}

		case evt := <-in:
			if x, ok := evt.(*transports.NetworkChangeEvent); ok && x != nil {
				t.discover_nat()
				t.handle_event(x, out)
			}
			out <- evt

		case <-ticker.C:
			t.discover_nat()

		}

		if t.nat != nil {
			return false // not done
		}
	}

	panic("unreachable")
}

func (t *transport) run_mapping_mode(done <-chan struct{}, in <-chan events.E, out chan<- events.E) bool {
	var ticker = time.NewTicker(50 * time.Minute)
	defer ticker.Stop()

	t.mapping = make(map[string]transports.Addr)

	for {
		select {

		case _, closed := <-done:
			if closed {
				return true // done
			}

		case evt := <-in:
			if x, ok := evt.(*transports.NetworkChangeEvent); ok && x != nil {
				t.handle_event(x, out)
			}
			out <- evt

		case <-ticker.C:
			t.refresh_mapping(out)

		}

		if t.nat == nil {
			if len(t.mapping) > 0 {
				evt := &transports.NetworkChangeEvent{}
				for _, addr := range t.mapping {
					evt.Down = append(evt.Down, addr)
				}
				out <- evt
			}

			t.mapping = nil
			return false // not done
		}
	}

	panic("unreachable")
}

func (t *transport) discover_nat() {
	nat, err := nat.Discover()
	if err != nil {
		return
	}

	_, err = nat.GetDeviceAddress()
	if err != nil {
		return
	}

	t.nat = nat
}

func (t *transport) handle_event(evt *transports.NetworkChangeEvent, out chan<- events.E) {
	var (
		down []transports.Addr
		up   []transports.Addr
	)

	external_ip, err := t.nat.GetExternalAddress()
	if err != nil {
		t.nat = nil
		return
	}

	internal_ip, err := t.nat.GetInternalAddress()
	if err != nil {
		t.nat = nil
		return
	}

	// unmap old addrs
	for _, addr := range evt.Down {
		nataddr, ok := addr.(NATableAddr)
		if !ok {
			continue
		}

		proto, ip, internal_port := nataddr.InternalAddr()
		if proto == "" || ip == nil || internal_port <= 0 {
			continue
		}

		key := mappingKey(proto, ip, internal_port)
		globaladdr := t.mapping[key]
		if globaladdr != nil {
			down = append(down, globaladdr)
			delete(t.mapping, key)
			t.nat.DeletePortMapping(proto, internal_port)
		}
	}

	// map new addrs
	for _, addr := range evt.Up {
		nataddr, ok := addr.(NATableAddr)
		if !ok {
			continue
		}

		proto, ip, internal_port := nataddr.InternalAddr()
		if proto == "" || ip == nil || internal_port <= 0 {
			continue
		}

		key := mappingKey(proto, ip, internal_port)
		if t.mapping[key] != nil {
			continue
		}

		if !ip.Equal(internal_ip) {
			continue
		}

		external_port, err := t.nat.AddPortMapping(proto, internal_port, "Telehash", 60*time.Minute)
		if err != nil {
			continue
		}

		globaddr := nataddr.MakeGlobal(external_ip, external_port)
		if globaddr == nil {
			continue
		}

		t.mapping[key] = globaddr
		up = append(up, globaddr)
	}

	if len(up) > 0 || len(down) > 0 {
		out <- &transports.NetworkChangeEvent{
			Up:   up,
			Down: down,
		}
	}
}

func (t *transport) refresh_mapping(out chan<- events.E) {
	var (
		up       []transports.Addr
		down     []transports.Addr
		droplist []string
	)

	external_ip, err := t.nat.GetExternalAddress()
	if err != nil {
		t.nat = nil
		return
	}

	internal_ip, err := t.nat.GetInternalAddress()
	if err != nil {
		t.nat = nil
		return
	}

	// map new addrs
	for key, addr := range t.mapping {
		nataddr, ok := addr.(NATableAddr)
		if !ok {
			droplist = append(droplist, key)
			down = append(down, addr)
			continue
		}

		proto, ip, internal_port := nataddr.InternalAddr()
		if proto == "" || ip == nil || internal_port <= 0 {
			droplist = append(droplist, key)
			down = append(down, addr)
			continue
		}

		if !ip.Equal(internal_ip) {
			droplist = append(droplist, key)
			down = append(down, addr)
			continue
		}

		external_port, err := t.nat.AddPortMapping(proto, internal_port, "Telehash", 60*time.Minute)
		if err != nil {
			droplist = append(droplist, key)
			down = append(down, addr)
			continue
		}

		globaddr := nataddr.MakeGlobal(external_ip, external_port)
		if globaddr == nil {
			droplist = append(droplist, key)
			down = append(down, addr)
			continue
		}

		if !transports.EqualAddr(addr, globaddr) {
			up = append(up, globaddr)
			down = append(down, addr)
		}

		t.mapping[key] = globaddr
	}

	for _, key := range droplist {
		delete(t.mapping, key)
	}

	if len(up) > 0 || len(down) > 0 {
		out <- &transports.NetworkChangeEvent{
			Up:   up,
			Down: down,
		}
	}
}

func mappingKey(proto string, ip net.IP, internal_port int) string {
	return fmt.Sprintf("%s:%s:%d", proto, ip, internal_port)
}
