package nat

import (
	"fmt"
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
	done    chan struct{}
}

func (c Config) Open() (transports.Transport, error) {
	t, err := c.Config.Open()
	if err != nil {
		return nil, err
	}

	nat := &transport{
		t:       t,
		mapping: make(map[string]transports.Addr),
		done:    make(chan struct{}),
	}

	go nat.run_mapper()

	return nat, nil
}

func (t *transport) LocalAddresses() []Addr {
	return t.t.LocalAddresses()
}

func (t *transport) ReadMessage(p []byte) (int, Addr, error) {
	return t.t.ReadMessage(p)
}

func (t *transport) WriteMessage(p []byte, dst Addr) error {
	return t.t.WriteMessage(p, dst)
}

func (t *transport) Close() error {
	select {
	case <-t.done: // is closed
	default: // is opened
		close(t.done)
	}

	return t.t.Close()
}

func (t *transport) run_mapper() {
	var closed bool
	for !closed {
		if t.nat == nil {
			closed = t.runDiscoverMode()
		} else {
			closed = t.runMappingMode()
		}
	}
}

func (t *transport) runDiscoverMode() bool {
	var discoverTicker = time.NewTicker(10 * time.Minute)
	defer discoverTicker.Stop()

	var updateTicker = time.NewTicker(5 * time.Second)
	defer updateTicker.Stop()

	var knownAddrs = make(map[string]bool)

	for {
		select {

		case <-done:
			return true // done

		case <-updateTicker.C:
			changed := t.updateKnownAddresses(knownAddrs)
			if changed {
				t.discoverNAT()
			}

		case <-discoverTicker.C:
			t.discoverNAT()

		}

		if t.nat != nil {
			return false // not done
		}
	}

	panic("unreachable")
}

func asNATableAddr(addr transports.Addr) (string, net.IP, int) {
	naddr, _ := addr.(NATableAddr)
	if naddr == nil {
		return "", nil, 0
	}

	proto, ip, port := naddr.InternalAddr()
	if proto == "" || ip == nil || internal_port <= 0 {
		return "", nil, 0
	}

	return proto, ip, port
}

func (t *transport) updateKnownAddresses(known map[string]bool) bool {
	var (
		changed bool
	)

	for key := range known {
		known[key] = false
	}

	for _, addr := range t.t.LocalAddresses() {
		proto, ip, internal_port := asNATableAddr(addr)
		if proto == "" {
			continue
		}

		key := mappingKey(proto, ip, internal_port)

		if _, found := known[key]; !found {
			changed = true
		}

		known[key] = true
	}

	for key, ok := range known {
		if !ok {
			delete(known, key)
			changed = true
		}
	}

	return changed
}

func (t *transport) runMappingMode() bool {
	var refreshTicker = time.NewTicker(50 * time.Minute)
	defer refreshTicker.Stop()

	var updateTicker = time.NewTicker(5 * time.Second)
	defer updateTicker.Stop()

	for {
		select {

		case <-done:
			t.mapping = make(map[string]transports.Addr)
			return true // done

		case <-refreshTicker.C:
			t.refreshMapping()

		case <-updateTicker.C:
			t.update_mappings()

		}

		if t.nat == nil {
			t.mapping = make(map[string]transports.Addr)
			return false // not done
		}
	}

	panic("unreachable")
}

func (t *transport) discoverNAT() {
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

func (t *transport) refreshMapping() {
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

	// remap addrs
	for key, addr := range t.mapping {
		proto, ip, internal_port := asNATableAddr(addr)
		if proto == "" {
			droplist = append(droplist, key)
			continue
		}

		// did our internal ip change?
		if !ip.Equal(internal_ip) {
			droplist = append(droplist, key)
			continue
		}

		external_port, err := t.nat.AddPortMapping(proto, internal_port, "Telehash", 60*time.Minute)
		if err != nil {
			droplist = append(droplist, key)
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
