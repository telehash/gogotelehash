package telehash

import (
	"bytes"
	"fmt"
	"net"
)

type IPv6NetPath struct {
	cat  ip_addr_category
	IP   net.IP
	Zone string
	Port int
}

func (n *IPv6NetPath) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 7
	case ip_lan:
		return 5
	case ip_wan:
		return 3
	default:
		return 0
	}
}

func (n *IPv6NetPath) Equal(o NetPath) bool {
	if m, ok := o.(*IPv6NetPath); ok {
		// also check zone?
		return n.Port == m.Port && bytes.Equal(n.IP, m.IP)
	} else {
		return false
	}
}

func (n *IPv6NetPath) AddressForSeek() (string, int, bool) {
	if n.cat != ip_wan {
		return "", 0, false
	}
	return n.IP.String(), n.Port, true
}

func (n *IPv6NetPath) String() string {
	return fmt.Sprintf("<net-ipv6 %s%%%s %s port=%d mtu=%d>", n.IP, n.Zone, n.cat, n.Port)
}

func (n *IPv6NetPath) ToUDPAddr(addr *net.UDPAddr) {
	addr.IP = n.IP
	addr.Port = n.Port
	addr.Zone = n.Zone
}
