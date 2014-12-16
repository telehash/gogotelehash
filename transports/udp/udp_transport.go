// Package udp implements the UDP transport.
//
// The UDP transport is NAT-able.
package udp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/telehash/gogotelehash/transports"
	// "github.com/telehash/gogotelehash/transports/nat"
)

// func init() {
// 	transports.RegisterAddrDecoder("udp4", decodeAddress)
// 	transports.RegisterAddrDecoder("udp6", decodeAddress)
// }

// Config for the UDP transport. Typically the zero value is sufficient to get started.
//
//   e3x.New(keys, udp.Config{})
type Config struct {
	// Can be set to UDPv4, UDPv6 or can be left blank.
	// Defaults to UDPv4
	Network string

	// Can be set to an address and/or port.
	// The zero value will bind it to a random port while listening on all interfaces.
	// When port is unspecified ("127.0.0.1") a random port will be chosen.
	// When ip is unspecified (":3000") the transport will listen on all interfaces.
	Addr string
}

const (
	// UDPv4 is used for IPv4 UDP networks
	UDPv4 = "udp4"
	// UDPv6 is used for IPv6 UDP networks
	UDPv6 = "udp6"
)

type connKey [18]byte

type transport struct {
	net   string
	laddr *net.UDPAddr
	c     *net.UDPConn

	mtx    sync.RWMutex
	conns  map[connKey]*connection
	closed bool

	mtxAccept   sync.Mutex
	cndAccept   *sync.Cond
	acceptQueue []*connection
}

type connection struct {
	transport *transport
	raddr     *net.UDPAddr

	mtx       sync.RWMutex
	cndRead   *sync.Cond
	closed    bool
	readQueue [][]byte
}

var (
	// _ nat.NATableAddr      = (*addr)(nil)
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

// Open opens the transport.
func (c Config) Open() (transports.Transport, error) {
	var (
		addr *net.UDPAddr
		err  error
	)

	if c.Network == "" {
		c.Network = UDPv4
	}
	if c.Addr == "" {
		c.Addr = ":0"
	}

	if c.Network != UDPv4 && c.Network != UDPv6 {
		return nil, errors.New("udp: Network must be either `udp4` or `udp6`")
	}

	{ // parse and verify source address
		addr, err = net.ResolveUDPAddr(c.Network, c.Addr)
		if err != nil {
			return nil, err
		}

		if c.Network == UDPv4 && addr.IP != nil && addr.IP.To4() == nil {
			return nil, errors.New("udp: expected a IPv4 address")
		}

		if c.Network == UDPv6 && addr.IP != nil && addr.IP.To4() != nil {
			return nil, errors.New("udp: expected a IPv6 address")
		}
	}

	conn, err := net.ListenUDP(c.Network, addr)
	if err != nil {
		return nil, err
	}

	addr = conn.LocalAddr().(*net.UDPAddr)

	t := &transport{net: c.Network, laddr: addr, c: conn}
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

	t.mtxAccept.Lock()
	defer t.mtxAccept.Unlock()

	err := t.c.Close()
	t.closed = true
	t.cndAccept.Broadcast()
	return err
}

func (t *transport) Dial(addr net.Addr) (net.Conn, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		conn, _ := t.getConnection(udpAddr)
		return conn, nil
	} else {
		return nil, &net.OpError{Op: "dial", Net: t.net, Addr: addr, Err: errors.New("invlaid address")}
	}
}

func (t *transport) Accept() (net.Conn, error) {
	t.mtxAccept.Lock()
	defer t.mtxAccept.Unlock()

	for len(t.acceptQueue) == 0 || t.closed {
		t.cndAccept.Wait()
	}

	if t.closed {
		return nil, io.EOF
	}

	conn := t.acceptQueue[0]
	copy(t.acceptQueue, t.acceptQueue[1:])
	t.acceptQueue = t.acceptQueue[:len(t.acceptQueue)-1]
	return conn, nil
}

func (t *transport) getConnection(addr *net.UDPAddr) (conn *connection, created bool) {
	var (
		k connKey
	)

	copy(k[:16], addr.IP.To16())
	binary.BigEndian.PutUint16(k[16:], uint16(addr.Port))

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
			conn.cndRead = sync.NewCond(&conn.mtx)
			t.conns[k] = conn
		}
		t.mtx.Unlock()
	}

	return conn, created
}

func (t *transport) dropConnection(addr *net.UDPAddr) {
	var (
		k     connKey
		conn1 *connection
		conn2 *connection
	)

	copy(k[:16], addr.IP.To16())
	binary.BigEndian.PutUint16(k[16:], uint16(addr.Port))

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
		n, addr, err := t.c.ReadFromUDP(b[:])
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
			conn.pushMessage(b[:n])
		}
	}
}

func (c *connection) pushMessage(p []byte) {
	c.mtx.Lock()

	if c.closed {
		c.mtx.Unlock()
		return
	}

	buf := make([]byte, len(p))
	copy(buf, p)
	c.readQueue = append(c.readQueue, buf)

	c.cndRead.Signal()
	c.mtx.Unlock()
}

func (c *connection) Read(b []byte) (n int, err error) {
	c.mtx.Lock()

	for !c.closed && len(c.readQueue) == 0 {
		c.cndRead.Wait()
	}
	if c.closed {
		c.mtx.Unlock()
		return 0, io.EOF
	}

	buf := c.readQueue[0]
	copy(b, buf)
	n = len(buf)

	copy(c.readQueue, c.readQueue[1:])
	c.readQueue = c.readQueue[:len(c.readQueue)-1]

	if len(c.readQueue) > 0 {
		c.cndRead.Signal()
	}

	c.mtx.Unlock()
	return n, nil
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

	return c.transport.c.WriteTo(b, c.raddr)
}

func (c *connection) Close() error {
	c.markAsClosed()
	c.transport.dropConnection(c.raddr)
	return nil
}

func (c *connection) markAsClosed() {
	c.mtx.Lock()
	c.closed = true
	c.cndRead.Signal()
	c.mtx.Unlock()
}

func (c *connection) LocalAddr() net.Addr {
	return c.transport.laddr
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) SetDeadline(t time.Time) error {
	// noop
	return nil
}

func (c *connection) SetReadDeadline(t time.Time) error {
	// noop
	return nil
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	// noop
	return nil
}

// func (t *transport) ReadMessage(p []byte) (int, transports.Addr, error) {
// 	const errUseOfClosedNet = "use of closed network connection"

// 	n, a, err := t.c.ReadFromUDP(p)
// 	if err != nil {
// 		if err.Error() == errUseOfClosedNet {
// 			err = transports.ErrClosed
// 		}
// 		return 0, nil, err
// 	}

// 	return n, &addr{net: t.net, UDPAddr: *a}, nil
// }

// func (t *transport) WriteMessage(p []byte, dst transports.Addr) error {
// 	a, ok := dst.(*addr)
// 	if !ok || a == nil {
// 		return transports.ErrInvalidAddr
// 	}

// 	if a.net != t.net {
// 		return transports.ErrInvalidAddr
// 	}

// 	if !t.dest.Contains(a.IP) {
// 		return transports.ErrInvalidAddr
// 	}

// 	n, err := t.c.WriteToUDP(p, &a.UDPAddr)
// 	if err != nil {
// 		return err
// 	}

// 	if n != len(p) {
// 		return io.ErrShortWrite
// 	}

// 	return nil
// }

func (t *transport) Addrs() []net.Addr {
	var (
		port  int
		addrs []net.Addr
	)

	{
		port = t.laddr.Port
		if !t.laddr.IP.IsUnspecified() {
			addrs = append(addrs, t.laddr)
			return addrs
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	for _, iface := range ifaces {
		iaddrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, iaddr := range iaddrs {
			var (
				ip   net.IP
				zone string
			)

			switch x := iaddr.(type) {
			case *net.IPAddr:
				ip = x.IP
				zone = x.Zone
			case *net.IPNet:
				ip = x.IP
				zone = ""
			}

			if ip.IsMulticast() ||
				ip.IsUnspecified() ||
				ip.IsInterfaceLocalMulticast() ||
				ip.IsLinkLocalMulticast() {
				continue
			}

			addrs = append(addrs, &net.UDPAddr{
				IP:   ip.To4(),
				Port: port,
				Zone: zone,
			})
		}
	}

	return addrs
}
