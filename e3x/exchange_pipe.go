package e3x

import (
	"io"
	"net"
	"sync"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/util/bufpool"
	"github.com/telehash/gogotelehash/util/tracer"
)

type pipe struct {
	mtx       sync.RWMutex
	wg        sync.WaitGroup
	closed    bool
	delegate  pipeDelegate
	transport transports.Transport
	raddr     net.Addr
	conn      net.Conn
}

type message struct {
	TID         tracer.ID
	Data        []byte
	Pipe        *pipe
	IsHandshake bool
}

type pipeDelegate interface {
	received(msg message)
}

func newMessage(msg []byte, p *pipe) message {
	isHandshake := false
	if len(msg) >= 3 && msg[0] == 0 && msg[1] == 1 {
		isHandshake = true
	}

	return message{tracer.NewID(), msg, p, isHandshake}
}

func newPipe(t transports.Transport, conn net.Conn, addr net.Addr, delegate pipeDelegate) *pipe {
	p := &pipe{transport: t, conn: conn, raddr: addr, delegate: delegate}

	if p.conn == nil && p.raddr == nil {
		panic("no connection information")
	}

	if p.raddr == nil {
		p.raddr = p.conn.RemoteAddr()
	}

	if p.conn != nil {
		p.wg.Add(1)
		go p.reader(p.conn)
	}

	return p
}

func (p *pipe) dial() (net.Conn, error) {
	var (
		conn   net.Conn
		closed bool
		dialed bool
		err    error
	)

	p.mtx.RLock()
	conn = p.conn
	closed = p.closed
	p.mtx.RUnlock()

	if closed {
		return nil, io.EOF
	}
	if conn != nil {
		return conn, err
	}

	p.mtx.Lock()
	if p.closed {
		err = io.EOF
	} else if p.conn == nil {
		conn, err = p.transport.Dial(p.raddr)
		if err == nil {
			p.conn = conn
			dialed = true
		}
	}
	conn = p.conn
	p.mtx.Unlock()

	if err != nil {
		return nil, err
	}

	if dialed {
		p.wg.Add(1)
		go p.reader(p.conn)
	}

	return conn, nil
}

func (p *pipe) RemoteAddr() net.Addr {
	return p.raddr
}

func (p *pipe) Write(b []byte) (int, error) {
	conn, err := p.dial()
	if err != nil {
		return 0, err
	}

	return conn.Write(b)
}

func (p *pipe) Close() error {
	var (
		conn   net.Conn
		closed bool
		err    error
	)

	p.mtx.RLock()
	conn, closed = p.conn, p.closed
	p.mtx.RUnlock()

	if closed {
		return nil
	}

	p.mtx.Lock()
	conn, closed = p.conn, p.closed
	p.conn, p.closed = nil, true
	p.mtx.Unlock()

	if conn != nil {
		err = conn.Close()
	}

	p.wg.Wait()
	return err
}

func (p *pipe) reader(conn net.Conn) {
	defer func() {
		p.mtx.Lock()
		if p.conn == conn {
			p.conn = nil
		}
		p.mtx.Unlock()

		p.wg.Done()
	}()

	for {
		buf := bufpool.GetBuffer()

		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		p.delegate.received(newMessage(buf[:n], p))
	}
}
