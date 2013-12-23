package telehash

import (
	"fmt"
	"hash/fnv"
	"net"
)

type IPv6NetPath struct {
	cat            ip_addr_category
	IP             net.IP
	Zone           string
	Port           int
	hash           uint32
	priority_delta net_path_priority
}

func (n *IPv6NetPath) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 7 + n.priority_delta.Get()
	case ip_lan:
		return 5 + n.priority_delta.Get()
	case ip_wan:
		return 3 + n.priority_delta.Get()
	default:
		return 0 + n.priority_delta.Get()
	}
}

func (n *IPv6NetPath) SendOpen() {
	n.priority_delta.Add(-1)
}

func (n *IPv6NetPath) ResetPriority() {
	n.priority_delta.Reset()
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
	return "", 0, false // only IPv4 in seek/see
}

func (n *IPv6NetPath) AddressForPeer() (string, int, bool) {
	return "", 0, false // only IPv4 in peer/connect
}

func (n *IPv6NetPath) SendNatBreaker() bool {
	return n.cat == ip_wan
}

func (n *IPv6NetPath) String() string {
	return fmt.Sprintf("<net-ipv6 %s%%%s %s port=%d>", n.IP, n.Zone, n.cat, n.Port)
}

func (n *IPv6NetPath) Send(sw *Switch, pkt *pkt_t) error {
	return ip_snd_pkt(sw, &net.UDPAddr{IP: n.IP, Port: n.Port}, pkt)
}
