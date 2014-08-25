package udp

import (
	"bytes"
	"encoding/json"
	"io"
	"net"

	"bitbucket.org/simonmenke/go-telehash/transports"
)

type addr net.UDPAddr

type transport struct {
	laddr *net.UDPAddr
	c     *net.UDPConn
}

var (
	_ transports.Addr      = (*addr)(nil)
	_ transports.Transport = (*transport)(nil)
)

func (t *transport) DefaultMTU() int {
	return 1450
}

func (t *transport) Open() error {
	c, err := net.ListenUDP("udp", t.laddr)
	if err != nil {
		return err
	}
	t.c = c
	return nil
}

func (t *transport) LocalAddresses() []transports.Addr {
	var (
		port  int
		addrs []transports.Addr
	)

	if a, ok := t.c.LocalAddr().(*net.UDPAddr); ok {
		port = a.Port
		if !a.IP.IsUnspecified() {
			switch a.Network() {
			case "udp":
				if v4 := a.IP.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						IP:   a.IP.To16(),
						Port: a.Port,
						Zone: a.Zone,
					})
				} else {
					addrs = append(addrs, &addr{
						IP:   v4,
						Port: a.Port,
						Zone: a.Zone,
					})
				}
			case "udp4":
				addrs = append(addrs, &addr{
					IP:   a.IP.To4(),
					Port: a.Port,
					Zone: a.Zone,
				})
			case "udp6":
				addrs = append(addrs, &addr{
					IP:   a.IP.To16(),
					Port: a.Port,
					Zone: a.Zone,
				})
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

			if v4 := ip.To4(); v4 != nil {
				addrs = append(addrs, &addr{
					IP:   v4,
					Port: port,
					Zone: zone,
				})
			} else {
				addrs = append(addrs, &addr{
					IP:   ip.To16(),
					Port: port,
					Zone: zone,
				})
			}
		}
	}

	return addrs
}

func (t *transport) Close() error {
	err := t.c.Close()
	t.c = nil
	return err
}

func (t *transport) Deliver(pkt []byte, to transports.Addr) error {
	n, err := t.c.WriteToUDP(pkt, (*net.UDPAddr)(to.(*addr)))
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return io.ErrShortWrite
	}
	return nil
}

func (t *transport) Receive(b []byte) (int, transports.Addr, error) {
	n, a, err := t.c.ReadFromUDP(b)
	if err != nil {
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

func (a *addr) Less(b transports.Addr) bool {
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
