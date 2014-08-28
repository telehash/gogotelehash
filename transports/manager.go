package transports

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/google/btree"

	"bitbucket.org/simonmenke/go-telehash/hashname"
)

type ManagerState uint8

const (
	UnknownManagerState ManagerState = iota
	RunningManagerState
	TerminatedManagerState
	BrokenManagerState
)

var ErrManagerTerminated = errors.New("transports: manager is terminated")

type Manager struct {
	stateMtx sync.Mutex
	wg       sync.WaitGroup
	state    ManagerState
	err      error

	transports      []Transport
	h2a             *btree.BTree
	a2h             *btree.BTree
	cAssociate      chan opAssociate
	cDeliver        chan opDeliver
	opReceive       *opReceive
	cReceive        chan *opReceive
	cReceived       chan opReceived
	cResolve        chan opResolve
	cLocalAddresses chan opLocalAddresses
	cTerminate      chan struct{}
}

type h2aItem struct {
	hn    hashname.H
	addrs []ResolvedAddr
}

type a2hItem struct {
	addr      ResolvedAddr
	hashnames map[hashname.H]bool
}

type opAssociate struct {
	hn   hashname.H
	addr ResolvedAddr
}

type opDeliver struct {
	pkt  []byte
	addr Addr
	cErr chan error
}

type opReceive struct {
	pkt   []byte
	addr  ResolvedAddr
	err   error
	cWait chan struct{}
}

type opReceived struct {
	pkt  []byte
	addr ResolvedAddr
}

type opResolve struct {
	addr Addr
	cRes chan []ResolvedAddr
}

type opLocalAddresses struct {
	cRes chan []ResolvedAddr
}

func (m *Manager) State() ManagerState {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()
	return m.state
}

func (m *Manager) AddTransport(t Transport) {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	m.transports = append(m.transports, t)
}

func (m *Manager) Start() error {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	err := m.start()
	if err != nil {
		m.stop()
		return err
	}

	return nil
}

func (m *Manager) start() error {
	if m.state == BrokenManagerState {
		return m.err
	}

	if m.state != UnknownManagerState {
		panic("transports: Manager cannot be started more than once")
	}

	m.h2a = btree.New(8)
	m.a2h = btree.New(8)
	m.cAssociate = make(chan opAssociate)
	m.cDeliver = make(chan opDeliver)
	m.cReceive = make(chan *opReceive)
	m.cReceived = make(chan opReceived)
	m.cResolve = make(chan opResolve)
	m.cLocalAddresses = make(chan opLocalAddresses)
	m.cTerminate = make(chan struct{}, 1)

	for _, t := range m.transports {
		err := t.Open()
		if err != nil {
			m.err = err
			m.state = BrokenManagerState
			return err
		}
	}

	for _, t := range m.transports {
		m.wg.Add(1)
		go m.run_receiver(t)
	}

	m.wg.Add(1)
	go m.run() // Run the main loop

	m.state = RunningManagerState
	return nil
}

func (m *Manager) Stop() error {
	m.stateMtx.Lock()
	defer m.stateMtx.Unlock()

	return m.stop()
}

func (m *Manager) stop() error {
	select {
	case m.cTerminate <- struct{}{}:
	default:
	}

	if m.opReceive != nil {
		m.opReceive.err = ErrManagerTerminated
		m.opReceive.cWait <- struct{}{}
		m.opReceive = nil
	}

	for _, t := range m.transports {
		err := t.Close()
		if err != nil && m.err == nil {
			m.state = BrokenManagerState
			m.err = err
		}
	}

	if m.state == RunningManagerState {
		m.state = TerminatedManagerState
	} else {
		m.state = BrokenManagerState
	}

	m.wg.Wait()
	return m.err
}

func (m *Manager) run() {
	defer m.wg.Done()

	for {
		var (
			cReceive  = m.cReceive
			cReceived = m.cReceived
		)

		if m.opReceive != nil {
			// waiting for packet
			cReceive = nil
		} else {
			// waiting for receive call
			cReceived = nil
		}

		select {

		case <-m.cTerminate:
			m.cTerminate <- struct{}{}
			return

		case op := <-m.cAssociate:
			m.associate(op)

		case op := <-m.cDeliver:
			op.cErr <- m.deliver(op)

		case op := <-cReceive:
			m.receive(op)

		case op := <-cReceived:
			m.received(op)

		case op := <-m.cResolve:
			op.cRes <- m.resolve(op.addr)

		case op := <-m.cLocalAddresses:
			op.cRes <- m.localAddresses()

		}
	}
}

func (m *Manager) run_receiver(t Transport) {
	defer m.wg.Done()

	for {
		var (
			buf = make([]byte, t.DefaultMTU())
		)

		n, addr, err := t.Receive(buf)
		if err == ErrTransportClosed {
			return
		}
		if err != nil {
			// report error
			continue
		}

		m.cReceived <- opReceived{buf[:n], addr}
	}
}

func (m *Manager) Associate(hn hashname.H, addr ResolvedAddr) {
	m.cAssociate <- opAssociate{hn, addr}
}

func (m *Manager) associate(op opAssociate) {
	h2aKey := h2aItem{hn: op.hn}
	h2a, ok := m.h2a.Get(&h2aKey).(*h2aItem)
	if !ok || h2a == nil {
		h2a = &h2aItem{hn: op.hn}
		m.h2a.ReplaceOrInsert(h2a)
	}

	a2hKey := a2hItem{addr: op.addr}
	a2h, ok := m.a2h.Get(&a2hKey).(*a2hItem)
	if !ok || a2h == nil {
		a2h = &a2hItem{addr: op.addr, hashnames: map[hashname.H]bool{}}
		m.a2h.ReplaceOrInsert(a2h)
	}

	found := false
	for _, o := range h2a.addrs {
		if !op.addr.Less(o) && !o.Less(op.addr) {
			found = true
			break
		}
	}
	if !found {
		h2a.addrs = append(h2a.addrs, op.addr)
	}

	a2h.hashnames[op.hn] = true
}

func (m *Manager) Deliver(pkt []byte, addr Addr) error {
	cErr := make(chan error)
	m.cDeliver <- opDeliver{pkt, addr, cErr}
	return <-cErr
}

func (m *Manager) deliver(op opDeliver) error {
	tracef("Deliver(%q)", op)

	var (
		errs      []error
		delivered bool
	)

	addrs := m.resolve(op.addr)
	if len(addrs) == 0 {
		return net.UnknownNetworkError(op.addr.String())
	}

	for _, transport := range m.transports {
		for _, addr := range addrs {
			if transport.CanDeliverTo(addr) {
				err := transport.Deliver(op.pkt, addr)
				if err == nil {
					delivered = true
				} else {
					errs = append(errs, err)
				}
			}
		}
	}

	if !delivered {
		return errs[0]
	}

	return nil
}

func (m *Manager) Receive() ([]byte, ResolvedAddr, error) {
	select {
	case <-m.cTerminate:
		m.cTerminate <- struct{}{}
		return nil, nil, ErrManagerTerminated
	default:
	}

	op := opReceive{cWait: make(chan struct{})}
	m.cReceive <- &op
	<-op.cWait
	return op.pkt, op.addr, op.err
}

func (m *Manager) receive(op *opReceive) {
	tracef("Receive(%q)", op)

	m.opReceive = op
}

func (m *Manager) received(op opReceived) {
	tracef("Received(%q)", op)

	m.opReceive.addr = op.addr
	m.opReceive.pkt = op.pkt
	m.opReceive.cWait <- struct{}{}
	m.opReceive = nil
}

func (m *Manager) LocalAddresses() []ResolvedAddr {
	cRes := make(chan []ResolvedAddr)
	m.cLocalAddresses <- opLocalAddresses{cRes}
	return <-cRes
}

func (m *Manager) localAddresses() []ResolvedAddr {
	var res []ResolvedAddr
	for _, t := range m.transports {
		res = append(res, t.LocalAddresses()...)
	}
	return res
}

func (m *Manager) Resolve(addr Addr) []ResolvedAddr {
	cRes := make(chan []ResolvedAddr)
	m.cResolve <- opResolve{addr, cRes}
	return <-cRes
}

func (m *Manager) resolve(addr Addr) []ResolvedAddr {
	tracef("Resolve(%q)", addr)

	if addr == nil {
		return nil
	}

	if a, ok := addr.(ResolvedAddr); ok && a != nil {
		return []ResolvedAddr{a}
	}

	a, ok := addr.(UnresolverAddr)
	if !ok {
		return nil
	}

	return a.Resolve(m)
}

func (a *h2aItem) Less(b btree.Item) bool {
	return a.hn.Less(b.(*h2aItem).hn)
}

func (a *a2hItem) Less(b btree.Item) bool {
	return a.addr.Less(b.(*a2hItem).addr)
}

type (
	allAddr  struct{ hn hashname.H }
	bestAddr struct{ hn hashname.H }
)

func All(hn hashname.H) UnresolverAddr {
	return &allAddr{hn}
}

func Best(hn hashname.H) UnresolverAddr {
	return &bestAddr{hn}
}

func (a *allAddr) String() string {
	return fmt.Sprintf(":all(%q)", a.hn)
}

func (a *allAddr) Resolve(m *Manager) []ResolvedAddr {
	h2aKey := h2aItem{hn: a.hn}
	h2a, _ := m.h2a.Get(&h2aKey).(*h2aItem)
	if h2a == nil || len(h2a.addrs) == 0 {
		return nil
	}
	return h2a.addrs
}

func (a *bestAddr) String() string {
	return fmt.Sprintf(":best(%q)", a.hn)
}

func (a *bestAddr) Resolve(m *Manager) []ResolvedAddr {
	h2aKey := h2aItem{hn: a.hn}
	h2a, _ := m.h2a.Get(&h2aKey).(*h2aItem)
	if h2a == nil || len(h2a.addrs) == 0 {
		return nil
	}
	return []ResolvedAddr{h2a.addrs[0]}
}
