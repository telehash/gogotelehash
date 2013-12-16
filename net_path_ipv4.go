package telehash

import (
	"fmt"
	"hash/fnv"
	"net"
)

type IPv4NetPath struct {
	cat            ip_addr_category
	IP             net.IP
	Port           int
	hash           uint32
	priority_delta net_path_priority
}

func (n *IPv4NetPath) Priority() int {
	// 1 = relay 2 = bridge 3-8 ip
	switch n.cat {
	case ip_localhost:
		return 8 + n.priority_delta.Get()
	case ip_lan:
		return 6 + n.priority_delta.Get()
	case ip_wan:
		return 4 + n.priority_delta.Get()
	default:
		return 0 + n.priority_delta.Get()
	}
}

func (n *IPv4NetPath) SendOpen() {
	n.priority_delta.Add(-1)
}

func (n *IPv4NetPath) ResetPriority() {
	n.priority_delta.Reset()
}

func (n *IPv4NetPath) Hash() uint32 {
	if n.hash == 0 {
		h := fnv.New32()
		fmt.Fprintln(h, "ipv4")
		fmt.Fprintln(h, n.IP.String())
		fmt.Fprintln(h, n.Port)
		n.hash = h.Sum32()
	}
	return n.hash
}

func (n *IPv4NetPath) AddressForSeek() (string, int, bool) {
	return n.IP.String(), n.Port, true
}

func (n *IPv4NetPath) AddressForPeer() (string, int, bool) {
	return n.IP.String(), n.Port, true
}

func (n *IPv4NetPath) SendNatBreaker() bool {
	return n.cat == ip_wan
}

func (n *IPv4NetPath) String() string {
	return fmt.Sprintf("<net-ipv4 %s %s port=%d>", n.IP, n.cat, n.Port)
}

func (n *IPv4NetPath) Send(sw *Switch, pkt *pkt_t) error {
	return ip_snd_pkt(sw, &net.UDPAddr{IP: n.IP, Port: n.Port}, pkt)
}
