package bridge

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/e3x"
	"github.com/telehash/gogotelehash/internal/hashname"
	"github.com/telehash/gogotelehash/internal/lob"
	"github.com/telehash/gogotelehash/internal/util/bufpool"
	"github.com/telehash/gogotelehash/transports/transportsutil"
)

var (
	_ net.Conn = (*connection)(nil)
)

type connection struct {
	target  hashname.H
	laddr   *peerAddr
	raddr   *peerAddr
	ex      *e3x.Exchange
	onClose func()

	mtx      sync.RWMutex
	halfPipe *transportsutil.HalfPipe
	closed   bool
}

func newConnection(target hashname.H, addr *peerAddr, ex *e3x.Exchange, onClose func()) *connection {
	c := &connection{target: target, laddr: addr, raddr: addr, ex: ex, onClose: onClose}
	c.halfPipe = transportsutil.NewHalfPipe()
	return c
}

func (c *connection) LocalAddr() net.Addr {
	return c.laddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) Write(b []byte) (int, error) {
	c.mtx.RLock()
	closed := c.closed
	c.mtx.RUnlock()

	if closed {
		return 0, io.EOF
	}

	if len(b) > 2 && b[0] == 0 && b[1] == 1 {
		return len(b), c.sendHandshake(b)
	}

	pipe := c.ex.ActivePipe()
	if pipe == nil {
		// drop
		return len(b), nil
	}

	buf := bufpool.New().Set(b)
	n, err := pipe.Write(buf)
	buf.Free()

	return n, err
}

func (c *connection) sendHandshake(body []byte) error {
	ch, err := c.ex.Open("peer", false)
	if err != nil {
		return err
	}

	// defer e3x.ForgetterFromEndpoint(c.ex.).ForgetChannel(ch)

	pkt := lob.New(body)
	pkt.Header().SetString("peer", string(c.target))
	ch.WritePacket(pkt)

	return nil
}

func (c *connection) Read(b []byte) (int, error) {
	return c.halfPipe.Read(b)
}

func (c *connection) Close() error {
	c.mtx.Lock()
	if c.closed {
		c.mtx.Unlock()
		return nil
	}

	c.closed = true
	c.mtx.Unlock()

	c.halfPipe.Close()
	if c.onClose != nil {
		c.onClose()
	}

	return nil
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
