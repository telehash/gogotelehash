package mux

import (
	"io"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/util/bufpool"
)

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*muxer)(nil)
)

type Config []transports.Config

type muxer struct {
	transports []transports.Transport
	cRead      chan readOp
}

type readOp struct {
	msg []byte
	src transports.Addr
	err error
}

func (c Config) Open() (transports.Transport, error) {
	m := &muxer{}
	m.cRead = make(chan readOp)

	for _, f := range c {
		t, err := f.Open()
		if err != nil {
			return nil, err
		}

		m.transports = append(m.transports, t)
	}

	for _, t := range m.transports {
		go m.runReader(t)
	}

	return m, nil
}

func (m *muxer) LocalAddresses() []transports.Addr {
	var addrs []transports.Addr

	for _, t := range m.transports {
		addrs = append(addrs, t.LocalAddresses()...)
	}

	return addrs
}

func (m *muxer) ReadMessage(p []byte) (n int, src transports.Addr, err error) {
	op := <-m.cRead

	if len(p) < len(op.msg) {
		return 0, nil, io.ErrShortBuffer
	}

	copy(p, op.msg)
	n = len(op.msg)
	src = op.src
	err = op.err

	bufpool.PutBuffer(op.msg)

	return
}

func (m *muxer) WriteMessage(p []byte, dst transports.Addr) error {
	for _, t := range m.transports {
		err := t.WriteMessage(p, dst)
		if err == transports.ErrInvalidAddr {
			continue
		}
		if err != nil {
			return err
		}
		if err == nil {
			return nil
		}
	}

	return transports.ErrInvalidAddr
}

func (m *muxer) Close() error {
	var lastErr error

	for _, t := range m.transports {
		err := t.Close()
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func (m *muxer) runReader(t transports.Transport) {
	for {
		buf := bufpool.GetBuffer()

		n, src, err := t.ReadMessage(buf)
		if err == transports.ErrClosed {
			return
		}

		m.cRead <- readOp{buf[:n], src, err}
	}
}
