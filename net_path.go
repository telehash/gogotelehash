package telehash

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

type NetPath struct {
	Name  string
	Flags net.Flags
	IP    net.IP
	Port  int
	MTU   int
}

func (n NetPath) IsMulticast() bool {
	return n.Flags&net.FlagMulticast > 0
}

func (n NetPath) IsBroadcast() bool {
	return n.Flags&net.FlagBroadcast > 0
}

func (n NetPath) IsLoopback() bool {
	return n.Flags&net.FlagLoopback > 0
}

func (n NetPath) IsPointToPoint() bool {
	return n.Flags&net.FlagPointToPoint > 0
}

func (n NetPath) IsIPv4() bool {
	if len(n.IP) == net.IPv4len {
		return true
	}
	if len(n.IP) == net.IPv6len && bytes.Equal(ipv6_mapped_ipv4_address_prefix, n.IP[:12]) {
		return true
	}
	return false
}

func (n NetPath) IsIPv6() bool {
	if len(n.IP) == net.IPv4len {
		return true
	}
	if len(n.IP) == net.IPv6len && !bytes.Equal(ipv6_mapped_ipv4_address_prefix, n.IP[:12]) {
		return true
	}
	return false
}

func (n NetPath) String() string {
	var (
		flags []string
		net   string
	)

	if n.IsLoopback() {
		flags = append(flags, "loopback")
	}
	if n.IsBroadcast() {
		flags = append(flags, "broadcast")
	}
	if n.IsPointToPoint() {
		flags = append(flags, "pointtopoint")
	}
	if n.IsMulticast() {
		flags = append(flags, "multicast")
	}

	if n.IsIPv4() {
		net = "ipv4"
	}
	if n.IsIPv6() {
		net = "ipv6"
	}

	return fmt.Sprintf("<net %s %s=%s port=%d mtu=%d flags=%s>", n.Name, net, n.IP, n.Port, n.MTU, strings.Join(flags, "|"))
}

func (n *NetPath) ToUDPAddr(addr *net.UDPAddr) {
	addr.IP = n.IP
	addr.Port = n.Port
}

func EqualNetPaths(a, b NetPath) bool {
	return a.Port == b.Port && bytes.Equal(a.IP, b.IP)
}

var ipv6_mapped_ipv4_address_prefix = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

func get_network_paths() ([]NetPath, error) {
	var (
		nets []NetPath
	)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addri := range addrs {
			switch addr := addri.(type) {
			case *net.IPNet:
				nets = append(nets, NetPath{iface.Name, iface.Flags &^ net.FlagUp, addr.IP, 0, iface.MTU})
			case *net.IPAddr:
				nets = append(nets, NetPath{iface.Name, iface.Flags &^ net.FlagUp, addr.IP, 0, iface.MTU})
			}
		}
	}

	return nets, nil
}

func (a NetPath) update(b NetPath) NetPath {
	if a.Name == "" {
		a.Name = b.Name
	}

	a.Flags = b.Flags
	if a.MTU > b.MTU && b.MTU > 0 {
		a.MTU = b.MTU
	}

	return a
}
