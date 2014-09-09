package udp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"bitbucket.org/simonmenke/go-telehash/transports"
	"bitbucket.org/simonmenke/go-telehash/transports/nat"
	"bitbucket.org/simonmenke/go-telehash/util/events"
)

func init() {
	transports.RegisterAddrDecoder("udp4", decodeAddress)
	transports.RegisterAddrDecoder("udp6", decodeAddress)
}

type Config struct {
	Network string // "udp4", "udp6"
	Addr    string
	Dest    string // CIDR format network range
}

type addr struct {
	net string
	net.UDPAddr
}

type transport struct {
	net       string
	laddr     *net.UDPAddr
	dest      *net.IPNet
	c         *net.UDPConn
	cEventOut chan<- events.E
}

var (
	_ transports.Addr      = (*addr)(nil)
	_ nat.NATableAddr      = (*addr)(nil)
	_ transports.Transport = (*transport)(nil)
	_ transports.Config    = Config{}
)

const (
	UDPv4 = "udp4"
	UDPv6 = "udp6"
)

func (c Config) Open(e chan<- events.E) (transports.Transport, error) {
	var (
		ipnet *net.IPNet
		addr  *net.UDPAddr
		err   error
	)

	if c.Network == "" {
		c.Network = UDPv4
	}
	if c.Addr == "" {
		c.Addr = ":0"
	}
	if c.Dest == "" {
		if c.Network == UDPv4 {
			c.Dest = "0.0.0.0/0"
		} else {
			c.Dest = "::0/0"
		}
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

	{ // parse and verify destination network
		_, ipnet, err = net.ParseCIDR(c.Dest)
		if err != nil {
			return nil, err
		}

		if c.Network == UDPv4 && ipnet.IP != nil && ipnet.IP.To4() == nil {
			return nil, errors.New("udp: expected a IPv4 network")
		}

		if c.Network == UDPv6 && ipnet.IP != nil && ipnet.IP.To4() != nil {
			return nil, errors.New("udp: expected a IPv6 network")
		}
	}

	conn, err := net.ListenUDP(c.Network, addr)
	if err != nil {
		return nil, err
	}

	addr = conn.LocalAddr().(*net.UDPAddr)

	t := &transport{c.Network, addr, ipnet, conn, e}

	go t.detect_network_changes()

	return t, nil
}

func (t *transport) detect_network_changes() {
	var (
		ticker = time.NewTicker(2 * time.Second)
		prev   map[string]transports.Addr
	)

	defer ticker.Stop()

	{
		addrs := t.LocalAddresses()
		prev = make(map[string]transports.Addr, len(addrs))
		for _, a := range addrs {
			prev[a.String()] = a
		}

		events.Emit(t.cEventOut, &transports.NetworkChangeEvent{Up: addrs})
	}

	for _ = range ticker.C {
		var (
			addrs = t.LocalAddresses()
			next  = make(map[string]transports.Addr, len(addrs))
			event = &transports.NetworkChangeEvent{}
		)

		for _, a := range addrs {
			key := a.String()
			next[key] = a
			if b, p := prev[key]; !p || b == nil {
				event.Up = append(event.Up, a)
			}
		}

		for k, a := range prev {
			if b, p := next[k]; !p || b == nil {
				event.Down = append(event.Down, a)
			}
		}

		prev = next

		if len(event.Up) == 0 && len(event.Down) == 0 {
			continue
		}

		if !events.Emit(t.cEventOut, event) {
			log.Printf("exit detect_network_changes()")
			break
		}
	}
}

func (t *transport) CanHandleAddress(a transports.Addr) bool {
	b, ok := a.(*addr)

	if !ok || b == nil {
		return false
	}

	if b.net != t.net {
		return false
	}

	if !t.dest.Contains(b.IP) {
		return false
	}

	return true
}

func decodeAddress(data []byte) (transports.Addr, error) {
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
	if ip == nil || ip.IsUnspecified() {
		return nil, transports.ErrInvalidAddr
	}

	if desc.Port <= 0 || desc.Port >= 65535 {
		return nil, transports.ErrInvalidAddr
	}

	return &addr{net: desc.Type, UDPAddr: net.UDPAddr{IP: ip, Port: desc.Port}}, nil
}

func (t *transport) LocalAddresses() []transports.Addr {
	var (
		port  int
		addrs []transports.Addr
	)

	{
		a := t.laddr
		port = a.Port
		if !a.IP.IsUnspecified() {
			switch t.net {

			case UDPv4:
				if v4 := a.IP.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						net: t.net,
						UDPAddr: net.UDPAddr{
							IP:   v4,
							Port: a.Port,
							Zone: a.Zone,
						},
					})
				}

			case UDPv6:
				if v4 := a.IP.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						net: t.net,
						UDPAddr: net.UDPAddr{
							IP:   a.IP.To16(),
							Port: a.Port,
							Zone: a.Zone,
						},
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

			if ip.IsMulticast() ||
				ip.IsUnspecified() ||
				ip.IsInterfaceLocalMulticast() ||
				ip.IsLinkLocalMulticast() {
				continue
			}

			switch t.net {

			case UDPv4:
				if v4 := ip.To4(); v4 != nil {
					addrs = append(addrs, &addr{
						net: t.net,
						UDPAddr: net.UDPAddr{
							IP:   ip.To4(),
							Port: port,
							Zone: zone,
						},
					})
				}

			case UDPv6:
				if v4 := ip.To4(); v4 == nil {
					addrs = append(addrs, &addr{
						net: t.net,
						UDPAddr: net.UDPAddr{
							IP:   ip.To16(),
							Port: port,
							Zone: zone,
						},
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

func (t *transport) Deliver(pkt []byte, to transports.Addr) error {
	a, ok := to.(*addr)
	if !ok || a == nil || a.net != t.net {
		return transports.ErrInvalidAddr
	}

	n, err := t.c.WriteToUDP(pkt, &a.UDPAddr)
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
		if err.Error() == "use of closed network connection" {
			return 0, nil, transports.ErrClosed
		}
		return 0, nil, err
	}
	return n, &addr{net: t.net, UDPAddr: *a}, nil
}

func (a *addr) Network() string {
	return a.net
}

func (a *addr) MarshalJSON() ([]byte, error) {
	var desc = struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}{
		Type: a.net,
		IP:   a.IP.String(),
		Port: a.Port,
	}
	return json.Marshal(&desc)
}

func (a *addr) Less(b transports.Addr) bool {
	if a.net < b.Network() {
		return true
	} else if a.net > b.Network() {
		return false
	}

	x := b.(*addr)
	if i := bytes.Compare(a.IP.To16(), x.IP.To16()); i < 0 {
		return true
	} else if i > 0 {
		return false
	}

	if a.Port < x.Port {
		return true
	} else if a.Port > x.Port {
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

func (a *addr) InternalAddr() (proto string, ip net.IP, port int) {
	if a == nil ||
		a.IP.IsLoopback() ||
		a.IP.IsMulticast() ||
		a.IP.IsUnspecified() ||
		a.IP.IsInterfaceLocalMulticast() ||
		a.IP.IsLinkLocalMulticast() {
		return "", nil, -1
	}
	return "udp", a.IP, a.Port
}

func (a *addr) MakeGlobal(ip net.IP, port int) transports.Addr {
	if a == nil {
		return nil
	}

	return &addr{a.net, net.UDPAddr{IP: ip, Port: port}}
}
