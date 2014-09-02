package udp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"

	"bitbucket.org/simonmenke/go-telehash/transports"
)

type addr net.UDPAddr

type Config struct {
	Network           string // "udp", "udp4", "udp6"
	Addr              string
	EnablePortMapping bool
}

type transport struct {
	net   string
	laddr *net.UDPAddr
	c     *net.UDPConn
}

var (
	_ transports.ResolvedAddr = (*addr)(nil)
	_ transports.Transport    = (*transport)(nil)
)

func (c Config) Open() (transports.Transport, error) {
	var (
		addr *net.UDPAddr
		err  error
	)

	if c.Network == "" {
		c.Network = "udp"
	}
	if c.Addr == "" {
		c.Addr = ":0"
	}

	addr, err = net.ResolveUDPAddr(c.Network, c.Addr)
	if err != nil {
		return nil, err
	}

	if c.Network == "udp" {
		if addr.IP == nil {
			// c.Network = "udp"
		} else if addr.IP.To4() != nil {
			c.Network = "udp4"
		} else {
			c.Network = "udp6"
		}
	}

	if c.Network == "udp4" && addr.IP != nil && addr.IP.To4() == nil {
		return nil, errors.New("udp: expected a IPv4 address")
	}

	if c.Network == "udp6" && addr.IP != nil && addr.IP.To4() != nil {
		return nil, errors.New("udp: expected a IPv6 address")
	}

	conn, err := net.ListenUDP(c.Network, addr)
	if err != nil {
		return nil, err
	}

	addr = conn.LocalAddr().(*net.UDPAddr)

	return &transport{net: c.Network, laddr: addr, c: conn}, nil
}

func (t *transport) Networks() []string {
	switch t.net {
	case "udp":
		return []string{"udp4", "udp6"}
	case "udp4":
		return []string{"udp4"}
	case "udp6":
		return []string{"udp6"}
	default:
		panic("unreachable")
	}
}

func (t *transport) DefaultMTU() int {
	return 1450
}

func (t *transport) DecodeAddress(data []byte) (transports.ResolvedAddr, error) {
	var desc struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}

	err := json.Unmarshal(data, &desc)
	if err != nil {
		return nil, transports.ErrInvalidAddr
	}

	ip := net.ParseIP(desc.IP)
	if ip == nil {
		return nil, transports.ErrInvalidAddr
	}

	if t.net == "udp4" && desc.Type != "udp4" {
		return nil, transports.ErrInvalidAddr
	}

	if t.net == "udp6" && desc.Type != "udp6" {
		return nil, transports.ErrInvalidAddr
	}

	return &addr{IP: ip, Port: desc.Port}, nil
}

func (t *transport) LocalAddresses() []transports.ResolvedAddr {
	var (
		port  int
		addrs []transports.ResolvedAddr
	)

	{
		a := t.laddr
		port = a.Port
		if !a.IP.IsUnspecified() {
			switch t.net {
			case "udp":
				if v4 := a.IP.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						IP:   v4,
						Port: a.Port,
						Zone: a.Zone,
					})
				}

				if v4 := a.IP.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						IP:   a.IP.To16(),
						Port: a.Port,
						Zone: a.Zone,
					})
				}

			case "udp4":
				if v4 := a.IP.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						IP:   v4,
						Port: a.Port,
						Zone: a.Zone,
					})
				}

			case "udp6":
				if v4 := a.IP.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						IP:   a.IP.To16(),
						Port: a.Port,
						Zone: a.Zone,
					})
				}

			}
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

			switch t.net {
			case "udp":
				if v4 := ip.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						IP:   v4,
						Port: port,
						Zone: zone,
					})
				}

				if v4 := ip.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						IP:   ip.To16(),
						Port: port,
						Zone: zone,
					})
				}

			case "udp4":
				if v4 := ip.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						IP:   ip.To4(),
						Port: port,
						Zone: zone,
					})
				}

			case "udp6":
				if v4 := ip.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						IP:   ip.To16(),
						Port: port,
						Zone: zone,
					})
				}

			}
		}
	}

	return addrs
}

func (t *transport) Close() error {
	err := t.c.Close()
	return err
}

func (t *transport) Deliver(pkt []byte, to transports.ResolvedAddr) error {
	n, err := t.c.WriteToUDP(pkt, (*net.UDPAddr)(to.(*addr)))
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return io.ErrShortWrite
	}
	return nil
}

func (t *transport) Receive(b []byte) (int, transports.ResolvedAddr, error) {
	n, a, err := t.c.ReadFromUDP(b)
	if err != nil {
		if err.Error() == "use of closed network connection" {
			return 0, nil, transports.ErrTransportClosed
		}
		return 0, nil, err
	}
	return n, (*addr)(a), nil
}

func (a *addr) Network() string {
	if a.IP.To4() == nil {
		return "udp6"
	} else {
		return "udp4"
	}
}

func (a *addr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}{
		Type: a.Network(),
		IP:   a.IP.String(),
		Port: a.Port,
	}
	return json.Marshal(&desc)
}

func (a *addr) Less(b transports.ResolvedAddr) bool {
	x := b.(*addr)
	if bytes.Compare(a.IP.To16(), x.IP.To16()) < 0 {
		return true
	}
	if a.Port < x.Port {
		return true
	}
	return false
}

func (a *addr) String() string {
	data, err := a.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return string(data)
}
