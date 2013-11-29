package telehash

import (
	"bytes"
	"fmt"
	"net"
)

type IPv4NetPath struct {
	cat  ip_addr_category
	IP   net.IP
	Port int
}

func (n *IPv4NetPath) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 8
	case ip_lan:
		return 6
	case ip_wan:
		return 4
	default:
		return 0
	}
}

func (n *IPv4NetPath) Equal(o NetPath) bool {
	if m, ok := o.(*IPv4NetPath); ok {
		return n.Port == m.Port && bytes.Equal(n.IP, m.IP)
	} else {
		return false
	}
}

func (n *IPv4NetPath) AddressForSeek() (string, int, bool) {
	if n.cat != ip_wan {
		return "", 0, false
	}
	return n.IP.String(), n.Port, true
}

func (n *IPv4NetPath) String() string {
	return fmt.Sprintf("<net-ipv4 %s %s port=%d mtu=%d>", n.IP, n.cat, n.Port)
}

func (n *IPv4NetPath) ToUDPAddr(addr *net.UDPAddr) {
	addr.IP = n.IP
	addr.Port = n.Port
}
