package e3x

import (
	"io"
	"net"
	"sync"

	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/internal/util/tracer"
	"github.com/telehash/gogotelehash/transports"
)

type Pipe struct {
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
	Data        *bufpool.Buffer
	Pipe        *Pipe
	IsHandshake bool
}

type pipeDelegate interface {
	received(msg message)
	dialDialerAddr(dialerAddr) (net.Conn, error)
}

type dialerAddr interface {
	Dial(e *Endpoint, x *Exchange) (net.Conn, error)
}

func newMessage(msg *bufpool.Buffer, p *Pipe) message {
	raw := msg.RawBytes()

	isHandshake := false
	if len(raw) >= 3 && raw[0] == 0 && raw[1] == 1 {
		isHandshake = true
	}

	return message{tracer.NewID(), msg, p, isHandshake}
}

func newPipe(t transports.Transport, conn net.Conn, addr net.Addr, delegate pipeDelegate) *Pipe {
	p := &Pipe{transport: t, conn: conn, raddr: addr, delegate: delegate}

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

func (p *Pipe) dial() (net.Conn, error) {
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
		if daddr, ok := p.raddr.(dialerAddr); ok {
			conn, err = p.delegate.dialDialerAddr(daddr)
		} else {
			conn, err = p.transport.Dial(p.raddr)
		}

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

func (p *Pipe) RemoteAddr() net.Addr {
	return p.raddr
}

func (p *Pipe) Write(b *bufpool.Buffer) (int, error) {
	conn, err := p.dial()
	if err != nil {
		return 0, err
	}

	return conn.Write(b.RawBytes())
}

func (p *Pipe) Close() error {
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

func (p *Pipe) reader(conn net.Conn) {
	defer func() {
		p.mtx.Lock()
		if p.conn == conn {
			p.conn = nil
		}
		p.mtx.Unlock()

		p.wg.Done()
	}()

	for {
		buf := bufpool.New()

		n, err := conn.Read(buf.RawBytes()[:1500])
		if err != nil {
			buf.Free()
			return
		}

		p.delegate.received(newMessage(buf.SetLen(n), p))
	}
}
