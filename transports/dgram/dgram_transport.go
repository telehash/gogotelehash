// Package dgram provides a wrapper for datagram based transports like UDP.
package dgram

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/transportsutil"
)

type Addr interface {
	net.Addr
	FillKey(k []byte)
}

type Transport interface {
	Addrs() []net.Addr

	NormalizeAddr(addr net.Addr) (Addr, error)
	Read(b []byte) (n int, addr Addr, err error)
	Write(b []byte, addr Addr) (n int, err error)

	Close() error
}

type transport struct {
	inner Transport

	mtx    sync.RWMutex
	conns  map[connKey]*connection
	closed bool

	mtxAccept   sync.Mutex
	cndAccept   *sync.Cond
	acceptQueue []*connection
}

type connection struct {
	transport *transport
	raddr     Addr

	mtx      sync.RWMutex
	closed   bool
	halfPipe *transportsutil.HalfPipe
}

type connKey [32]byte

var (
	_ transports.Transport = (*transport)(nil)
)

// Wrap a drgram transport in a stream Transport
func Wrap(inner Transport) (transports.Transport, error) {
	t := &transport{inner: inner}
	t.cndAccept = sync.NewCond(&t.mtxAccept)

	go t.reader()

	return t, nil
}

func (t *transport) Close() error {
	t.mtx.Lock()
	defer t.mtx.Unlock()

	if t.closed {
		return nil
	}

	for _, conn := range t.conns {
		conn.markAsClosed()
	}

	t.mtxAccept.Lock()
	defer t.mtxAccept.Unlock()

	err := t.inner.Close()
	t.closed = true
	t.cndAccept.Broadcast()
	return err
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	daddr, err := t.inner.NormalizeAddr(addr)
	if err != nil {
		return nil, err
	}

	conn, _ := t.getConnection(daddr)
	return conn, nil
}

func (t *transport) Accept() (net.Conn, error) {
	t.mtxAccept.Lock()
	defer t.mtxAccept.Unlock()

	for len(t.acceptQueue) == 0 && !t.closed {
		t.cndAccept.Wait()
	}

	if t.closed {
		return nil, io.EOF
	}

	conn := t.acceptQueue[0]
	copy(t.acceptQueue, t.acceptQueue[1:])
	t.acceptQueue = t.acceptQueue[:len(t.acceptQueue)-1]

	if len(t.acceptQueue) > 0 {
		t.cndAccept.Signal()
	}

	return conn, nil
}

func (t *transport) getConnection(addr Addr) (conn *connection, created bool) {
	var (
		k connKey
	)

	addr.FillKey(k[:])

	t.mtx.RLock()
	if t.conns != nil {
		conn = t.conns[k]
	}
	t.mtx.RUnlock()

	if conn == nil {
		t.mtx.Lock()
		if t.conns == nil {
			t.conns = make(map[connKey]*connection)
		}
		conn = t.conns[k]
		if conn == nil {
			created = true
			conn = &connection{transport: t, raddr: addr}
			conn.halfPipe = transportsutil.NewHalfPipe()
			t.conns[k] = conn
		}
		t.mtx.Unlock()
	}

	return conn, created
}

func (t *transport) dropConnection(addr Addr) {
	var (
		k     connKey
		conn1 *connection
		conn2 *connection
	)

	addr.FillKey(k[:])

	// still there?
	t.mtx.RLock()
	if t.conns != nil {
		conn1 = t.conns[k]
	}
	t.mtx.RUnlock()

	if conn1 == nil {
		return
	}

	t.mtx.Lock()
	conn2 = t.conns[k]
	if conn2 != nil && conn2 == conn1 {
		// remove if still there
		delete(t.conns, k)
	}
	t.mtx.Unlock()

	if conn2 != nil {
		conn2.markAsClosed()
	}
}

func (t *transport) reader() {
	var b [1500]byte

	for {
		n, addr, err := t.inner.Read(b[:])
		if err != nil {
			return
		}

		conn, created := t.getConnection(addr)
		queued := false

		if created {
			t.mtxAccept.Lock()
			if len(t.acceptQueue) < 1024 {
				t.acceptQueue = append(t.acceptQueue, conn)
				t.cndAccept.Signal()
				queued = true
			}
			t.mtxAccept.Unlock()

			if !queued {
				t.dropConnection(addr)
				conn = nil
			}
		}

		if conn != nil {
			conn.halfPipe.PushMessage(b[:n])
		}
	}
}

func (c *connection) Read(b []byte) (n int, err error) {
	return c.halfPipe.Read(b)
}

func (c *connection) Write(b []byte) (n int, err error) {
	if len(b) > 1472 {
		return 0, io.ErrShortWrite
	}

	c.mtx.RLock()
	if c.closed {
		c.mtx.RUnlock()
		return 0, io.EOF
	}
	c.mtx.RUnlock()

	return c.transport.inner.Write(b, c.raddr)
}

func (c *connection) Close() error {
	c.markAsClosed()
	c.transport.dropConnection(c.raddr)
	return nil
}

func (c *connection) markAsClosed() {
	c.mtx.Lock()
	c.halfPipe.Close()
	c.closed = true
	c.mtx.Unlock()
}

func (c *connection) LocalAddr() net.Addr {
	addrs := c.transport.Addrs()
	if len(addrs) > 0 {
		return addrs[0]
	}
	return nil
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) SetDeadline(t time.Time) error {
	return c.halfPipe.SetReadDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.halfPipe.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	// noop
	return nil
}

func (t *transport) Addrs() []net.Addr {
	return t.inner.Addrs()
}
