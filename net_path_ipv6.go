package telehash

import (
	"fmt"
	"hash/fnv"
	"net"
)

type IPv6NetPath struct {
	cat  ip_addr_category
	IP   net.IP
	Zone string
	Port int
	hash uint32
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

func (n *IPv6NetPath) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "ipv6")
		fmt.Fprintln(h, n.IP.String())
		fmt.Fprintln(h, n.Port)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *IPv6NetPath) AddressForSeek() (string, int, bool) {
	return "", 0, false // no IPv6 for now
}

func (n *IPv6NetPath) AddressForPeer() (string, int, bool) {
	return "", 0, false // no IPv6 for now
}

func (n *IPv6NetPath) String() string {
	return fmt.Sprintf("<net-ipv6 %s%%%s %s port=%d mtu=%d>", n.IP, n.Zone, n.cat, n.Port)
}

func (n *IPv6NetPath) Send(sw *Switch, pkt *pkt_t) error {
	return ip_snd_pkt(sw, &net.UDPAddr{IP: n.IP, Port: n.Port}, pkt)
}
