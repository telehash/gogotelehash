// Package tcp implements the TCP transport.
package tcp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/transportsutil"
)

// Config for the TCP transport. Typically the zero value is sufficient to get started.
//
//   e3x.New(keys, udp.Config{})
type Config struct {
	// Can be set to TCPv4, TCPv6 or can be left blank.
	// Defaults to TCPv4
	Network string

	// Can be set to an address and/or port.
	// The zero value will bind it to a random port while listening on all interfaces.
	// When port is unspecified ("127.0.0.1") a random port will be chosen.
	// When ip is unspecified (":3000") the transport will listen on all interfaces.
	Addr string
}

const (
	// TCPv4 is used for IPv4 TCP networks
	TCPv4 = "tcp4"
	// TCPv6 is used for IPv6 TCP networks
	TCPv6 = "tcp6"
)

type transport struct {
	net      string
	laddr    tcpAddr
	listener *net.TCPListener
}

type connection struct {
	transport *transport
	raddr     tcpAddr
	conn      *net.TCPConn
	bufr      *bufio.Reader
	mtxWrite  sync.Mutex
	mtxRead   sync.Mutex
}

var (
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

// Open opens the transport.
func (c Config) Open() (transports.Transport, error) {
	var (
		addr *net.TCPAddr
		err  error
	)

	if c.Network == "" {
		c.Network = TCPv4
	}
	if c.Addr == "" {
		c.Addr = ":0"
	}

	if c.Network != TCPv4 && c.Network != TCPv6 {
		return nil, errors.New("tcp: Network must be either `tcp4` or `tcp6`")
	}

	{ // parse and verify source address
		addr, err = net.ResolveTCPAddr(c.Network, c.Addr)
		if err != nil {
			return nil, err
		}

		if c.Network == TCPv4 && addr.IP != nil && !ipIs4(addr.IP) {
			return nil, errors.New("tcp: expected a IPv4 address")
		}

		if c.Network == TCPv6 && addr.IP != nil && ipIs4(addr.IP) {
			return nil, errors.New("tcp: expected a IPv6 address")
		}
	}

	listener, err := net.ListenTCP(c.Network, addr)
	if err != nil {
		return nil, err
	}

	addr = listener.Addr().(*net.TCPAddr)

	return &transport{net: c.Network, laddr: wrapAddr(addr), listener: listener}, nil
}

func (t *transport) Addrs() []net.Addr {
	var (
		port  uint16
		addrs []net.Addr
	)

	{
		port = t.laddr.GetPort()
		if !t.laddr.GetIP().IsUnspecified() {
			addrs = append(addrs, t.laddr)
			return addrs
		}
	}

	ips, err := transportsutil.InterfaceIPs()
	if err != nil {
		return addrs
	}

	for _, addr := range ips {
		addr := wrapAddr(&net.TCPAddr{
			IP:   addr.IP,
			Zone: addr.Zone,
			Port: int(port),
		})
		if (addr.IsIPv6() && t.net == TCPv6) || (!addr.IsIPv6() && t.net == TCPv4) {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	switch x := addr.(type) {
	case tcpAddr:
		conn, err := net.DialTCP("tcp", nil, x.ToTCPAddr())
		if err != nil {
			return nil, err
		}

		return &connection{transport: t, raddr: x, conn: conn, bufr: bufio.NewReader(conn)}, nil
	case *net.TCPAddr:
		return t.Dial(wrapAddr(x))
	default:
		return nil, transports.ErrInvalidAddr
	}
}

func (t *transport) Accept() (c net.Conn, err error) {
	tconn, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	raddr := tconn.RemoteAddr().(*net.TCPAddr)

	conn := &connection{transport: t, raddr: wrapAddr(raddr), conn: tconn, bufr: bufio.NewReader(tconn)}
	return conn, nil
}

func (t *transport) Close() error {
	return t.listener.Close()
}

func (c *connection) Read(b []byte) (n int, err error) {
	var hdr [2]byte

	c.mtxRead.Lock()
	defer c.mtxRead.Unlock()

	_, err = io.ReadFull(c.bufr, hdr[:])
	if err != nil {
		return 0, err
	}

	msgLen := binary.BigEndian.Uint16(hdr[:])

	return io.ReadFull(c.bufr, b[:msgLen])
}

func (c *connection) Write(b []byte) (n int, err error) {
	var lenB = len(b)
	if lenB > 1472 {
		return 0, io.ErrShortWrite
	}

	var hdr [2]byte
	var hdrP = hdr[:]
	binary.BigEndian.PutUint16(hdrP, uint16(lenB))

	c.mtxWrite.Lock()
	defer c.mtxWrite.Unlock()

	for len(hdrP) > 0 {
		n, err := c.conn.Write(hdrP)
		if err != nil {
			return 0, err
		}
		hdrP = hdrP[n:]
	}

	for len(b) > 0 {
		n, err := c.conn.Write(b)
		if err != nil {
			return 0, err
		}
		b = b[n:]
	}

	return lenB, nil
}

func (c *connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *connection) LocalAddr() net.Addr {
	return c.transport.laddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) Close() error {
	return c.conn.Close()
}
