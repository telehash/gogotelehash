// Package mux implements a transport muxer.
//
// This package provides a transport that transparently merges multiple sub-transports
// as-if they are one.
package mux

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/transports"
)

var (
	_ transports.Config    = Config{}
	_ transports.Transport = (*transport)(nil)
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

type transport struct {
	transports []transports.Transport
	cAccept    chan net.Conn
	wg         sync.WaitGroup
}

// Open opens the sub-transports.
func (c Config) Open() (transports.Transport, error) {
	t := &transport{}
	t.cAccept = make(chan net.Conn)

	for _, f := range c {
		s, err := f.Open()
		if err != nil {
			return nil, err
		}

		t.transports = append(t.transports, s)
	}

	for _, s := range t.transports {
		t.wg.Add(1)
		go t.runAccepter(s)
	}

	return t, nil
}

func (t *transport) Addrs() []net.Addr {
	var addrs []net.Addr

	for _, s := range t.transports {
		addrs = append(addrs, s.Addrs()...)
	}

	return addrs
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	for _, s := range t.transports {
		conn, err := s.Dial(addr)
		if err == transports.ErrInvalidAddr {
			continue
		}
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	return nil, transports.ErrInvalidAddr
}

func (t *transport) Accept() (c net.Conn, err error) {
	conn, ok := <-t.cAccept
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (m *transport) Close() error {
	var lastErr error

	for _, t := range m.transports {
		err := t.Close()
		if err != nil {
			lastErr = err
		}
	}

	m.wg.Wait()
	close(m.cAccept)

	return lastErr
}

func (t *transport) runAccepter(s transports.Transport) {
	defer t.wg.Done()
	for {
		conn, err := s.Accept()
		if err == io.EOF {
			break
		}
		if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			return
		}

		t.cAccept <- conn
	}
}
