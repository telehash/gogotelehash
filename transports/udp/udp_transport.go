// Package udp implements the UDP transport.
//
// The UDP transport is NAT-able.
package udp

import (
	"errors"
	"net"

	"github.com/telehash/gogotelehash/transports"
	"github.com/telehash/gogotelehash/transports/dgram"
	"github.com/telehash/gogotelehash/transports/transportsutil"
)

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

type transport struct {
	net   string
	laddr udpAddr
	c     *net.UDPConn
}

var (
	_ dgram.Transport   = (*transport)(nil)
	_ transports.Config = Config{}
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

		if c.Network == UDPv4 && addr.IP != nil && !ipIs4(addr.IP) {
			return nil, errors.New("udp: expected a IPv4 address")
		}

		if c.Network == UDPv6 && addr.IP != nil && ipIs4(addr.IP) {
			return nil, errors.New("udp: expected a IPv6 address")
		}
	}

	conn, err := net.ListenUDP(c.Network, addr)
	if err != nil {
		return nil, err
	}

	addr = conn.LocalAddr().(*net.UDPAddr)

	t := &transport{net: c.Network, laddr: wrapAddr(addr), c: conn}
	return dgram.Wrap(t)
}

func (t *transport) Close() error {
	return t.c.Close()
}

func (t *transport) NormalizeAddr(addr net.Addr) (dgram.Addr, error) {
	if a, ok := addr.(*net.UDPAddr); ok {
		return t.NormalizeAddr(wrapAddr(a))
	} else if a, ok := addr.(*udpv4); ok && t.net == UDPv4 {
		return a, nil
	} else if a, ok := addr.(*udpv6); ok && t.net == UDPv6 {
		return a, nil
	} else {
		return nil, transports.ErrInvalidAddr
	}
}

func (t *transport) Read(b []byte) (n int, addr dgram.Addr, err error) {
	n, uaddr, err := t.c.ReadFromUDP(b)
	if err != nil {
		return 0, nil, err
	}
	return n, wrapAddr(uaddr), nil
}

func (t *transport) Write(b []byte, addr dgram.Addr) (n int, err error) {
	return t.c.WriteToUDP(b, addr.(udpAddr).ToUDPAddr())
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
		addr := wrapAddr(&net.UDPAddr{
			IP:   addr.IP,
			Zone: addr.Zone,
			Port: int(port),
		})
		if addr.IsIPv6() && t.net == UDPv6 || !addr.IsIPv6() && t.net == UDPv4 {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}
