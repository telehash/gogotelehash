package mux

import (
	"errors"
	"io"
	"net"
	"sync"

	"bitbucket.org/simonmenke/go-telehash/transports"
)

var ErrmuxerTerminated = errors.New("transports: manager is terminated")

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*muxer)(nil)
)

type Config []transports.Config

type muxer struct {
	wg  sync.WaitGroup
	err error

	transports []transports.Transport

	cDeliver        chan *opDeliver
	opReceive       *opReceive
	cReceive        chan *opReceive
	cReceived       chan *opReceived
	cLocalAddresses chan *opLocalAddresses
	cTerminate      chan struct{}
}

type opDeliver struct {
	pkt  []byte
	addr transports.Addr
	cErr chan error
}

type opReceive struct {
	buf   []byte
	addr  transports.Addr
	err   error
	cWait chan struct{}
}

type opReceived struct {
	pkt  []byte
	addr transports.Addr
}

type opLocalAddresses struct {
	cRes chan []transports.Addr
}

func (c Config) Open() (transports.Transport, error) {
	m := &muxer{}

	m.cDeliver = make(chan *opDeliver)
	m.cReceive = make(chan *opReceive)
	m.cReceived = make(chan *opReceived)
	m.cLocalAddresses = make(chan *opLocalAddresses)
	m.cTerminate = make(chan struct{})

	for _, f := range c {
		t, err := f.Open()
		if err != nil {
			return nil, err
		}

		m.transports = append(m.transports, t)
	}

	// run the receivers
	for _, t := range m.transports {
		m.wg.Add(1)
		go m.run_receiver(t)
	}

	m.wg.Add(1)
	go m.run() // Run the main loop

	return m, nil
}

func (m *muxer) CanHandleAddress(a transports.Addr) bool {
	for _, t := range m.transports {
		if t.CanHandleAddress(a) {
			return true
		}
	}
	return false
}

func (m *muxer) Close() error {
	if detectClosed(func() { m.cTerminate <- struct{}{} }) {
		return transports.ErrClosed
	}

	// wait until terminated
	m.wg.Wait()

	return m.err
}

func (m *muxer) close() {
	if m.opReceive != nil {
		m.opReceive.err = transports.ErrClosed
		m.opReceive.cWait <- struct{}{}
		m.opReceive = nil
	}

	for _, t := range m.transports {
		err := t.Close()
		if err != nil && m.err == nil {
			m.err = err
		}
	}

	close(m.cDeliver)
	close(m.cReceive)
	close(m.cReceived)
	close(m.cTerminate)
	close(m.cLocalAddresses)
}

func (m *muxer) run() {
	defer m.wg.Done()
	defer m.close()

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
			return

		case op := <-m.cLocalAddresses:
			op.cRes <- m.localAddresses()

		case op := <-m.cDeliver:
			op.cErr <- m.deliver(op)

		case op := <-cReceive:
			m.receive(op)

		case op := <-cReceived:
			m.received(op)

		}
	}
}

func (m *muxer) run_receiver(t transports.Transport) {
	defer m.wg.Done()

	for {
		var (
			buf = transports.GetBuffer()
			op  opReceived
		)

		n, addr, err := t.Receive(buf)
		if err == transports.ErrClosed {
			transports.PutBuffer(buf)
			return
		}
		if err != nil {
			// report error
			transports.PutBuffer(buf)
			continue
		}

		op = opReceived{buf[:n], addr}
		if detectClosed(func() { m.cReceived <- &op }) {
			return
		}
	}
}

func (m *muxer) Deliver(pkt []byte, addr transports.Addr) error {
	op := opDeliver{pkt, addr, make(chan error)}

	if detectClosed(func() { m.cDeliver <- &op }) {
		return transports.ErrClosed
	}

	return <-op.cErr
}

func (m *muxer) deliver(op *opDeliver) error {
	// tracef("Deliver(%q)", op)

	if op.addr == nil {
		return net.UnknownNetworkError("no address")
	}

	var errs []error

	for _, t := range m.transports {
		if !t.CanHandleAddress(op.addr) {
			continue
		}

		err := t.Deliver(op.pkt, op.addr)
		if err != nil {
			errs = append(errs, err)
		} else {
			return nil
		}
	}

	if len(errs) == 0 {
		return net.UnknownNetworkError(op.addr.String())
	}

	return errs[0]
}

func (m *muxer) Receive(p []byte) (int, transports.Addr, error) {
	op := opReceive{buf: p, cWait: make(chan struct{})}

	if detectClosed(func() { m.cReceive <- &op }) {
		return 0, nil, transports.ErrClosed
	}

	<-op.cWait

	if len(op.buf) > len(p) {
		transports.PutBuffer(op.buf)
		return 0, op.addr, io.ErrShortBuffer
	}

	copy(p, op.buf)
	n := len(op.buf)

	if op.buf != nil {
		transports.PutBuffer(op.buf)
	}

	return n, op.addr, op.err
}

func (m *muxer) receive(op *opReceive) {
	// tracef("Receive(%q)", op)

	m.opReceive = op
}

func (m *muxer) received(op *opReceived) {
	// tracef("Received(%q)", op)

	m.opReceive.addr = op.addr
	m.opReceive.buf = op.pkt
	m.opReceive.cWait <- struct{}{}
	m.opReceive = nil
}

func (m *muxer) LocalAddresses() []transports.Addr {
	op := opLocalAddresses{make(chan []transports.Addr)}

	if detectClosed(func() { m.cLocalAddresses <- &op }) {
		return nil
	}

	return <-op.cRes
}

func (m *muxer) localAddresses() []transports.Addr {
	var res []transports.Addr
	for _, t := range m.transports {
		res = append(res, t.LocalAddresses()...)
	}
	return res
}

func detectClosed(f func()) (closed bool) {
	defer func() { closed = recover() != nil }()
	f()
	return false
}
