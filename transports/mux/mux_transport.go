// Package mux implements a transport muxer.
//
// This package provides a transport that transparently merges multiple sub-transports
// as-if they are one.
package mux

import (
	"io"
	"sync"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/bufpool"
)

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*muxer)(nil)
)

// Config is a list of sub-transport configurations.
//
//   e3x.New(keys, nat.Config{mux.Config{
//     udp.Config{},
//     webrtc.Config{},
//     tcp.Config{MaxSessions: 150},
//     http.Config{MaxSessions: 150},
//   }})
type Config []transports.Config

type muxer struct {
	transports []transports.Transport
	cRead      chan readOp
	wg         sync.WaitGroup
}

type readOp struct {
	msg []byte
	src transports.Addr
	err error
}

// Open opens the sub-transports.
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
		m.wg.Add(1)
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
	op, ok := <-m.cRead

	if !ok {
		return 0, nil, transports.ErrClosed
	}

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

	close(m.cRead)

	for _, t := range m.transports {
		err := t.Close()
		if err != nil {
			lastErr = err
		}
	}

	m.wg.Wait()

	return lastErr
}

func (m *muxer) runReader(t transports.Transport) {
	defer m.wg.Done()
	for {
		buf := bufpool.GetBuffer()

		n, src, err := t.ReadMessage(buf)
		if err == transports.ErrClosed {
			return
		}

		func() {
			defer func() { recover() }()
			m.cRead <- readOp{buf[:n], src, err}
		}()
	}
}
