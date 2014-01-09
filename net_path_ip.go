package telehash

import (
	"bytes"
	"net"
	"sync/atomic"
)

func ParseIPnet_path(str string) (net_path, error) {
	addr, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		return nil, err
	}

	return net_pathFromAddr(addr), nil
}

func net_pathFromAddr(addri net.Addr) net_path {
	if addri == nil {
		return nil
	}

	var (
		ip   net.IP
		zone string
		port int
		cat  ip_addr_category
	)

	switch addr := addri.(type) {
	case *net.IPNet:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
		zone = addr.Zone
	case *net.UDPAddr:
		ip = addr.IP
		zone = addr.Zone
		port = addr.Port
	case *net.TCPAddr:
		ip = addr.IP
		zone = addr.Zone
		port = addr.Port
	}

	if is_local_ip(ip) {
		cat = ip_localhost
	} else if is_lan_ip(ip) {
		cat = ip_lan
	} else {
		cat = ip_wan
	}

	if is_ipv4(ip) {
		return &IPv4net_path{cat, ip, port, 0, 0}
	} else {
		return &IPv6net_path{cat, ip, zone, port, 0, 0}
	}
}

type ip_addr_category uint8

const (
	ip_unknown ip_addr_category = iota
	ip_localhost
	ip_lan
	ip_wan
)

var ip_addr_category_strings = map[ip_addr_category]string{
	ip_unknown:   "unknown",
	ip_localhost: "local",
	ip_lan:       "lan",
	ip_wan:       "wan",
}

func (c ip_addr_category) String() string {
	return ip_addr_category_strings[c]
}

func get_network_paths(port int) ([]*net_path, error) {
	var (
		nets []net_path
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

		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				nets = append(nets, net_pathFromAddr(&net.UDPAddr{IP: a.IP, Port: port}))
			}
		}
	}

	return nets, nil
}

var ipv6_mapped_ipv4_address_prefix = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

func is_ipv4(ip net.IP) bool {
	if len(ip) == net.IPv4len {
		return true
	}
	if len(ip) == net.IPv6len && bytes.Equal(ipv6_mapped_ipv4_address_prefix, ip[:12]) {
		return true
	}
	return false
}

var lan_ranges = []net.IPNet{
	{net.IPv4(10, 0, 0, 0), net.CIDRMask(8, 32)},
	{net.IPv4(172, 16, 0, 0), net.CIDRMask(12, 32)},
	{net.IPv4(192, 168, 0, 0), net.CIDRMask(16, 32)},
	{net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.CIDRMask(7, 128)},
}

func is_lan_ip(ip net.IP) bool {
	for _, net := range lan_ranges {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

var local_ranges = []net.IPNet{
	{net.IPv4(127, 0, 0, 0), net.CIDRMask(8, 32)},
	{net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}, net.CIDRMask(128, 128)},
}

func is_local_ip(ip net.IP) bool {
	for _, net := range local_ranges {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

var nat_breaker_pkt = &pkt_t{}

func ip_snd_pkt(sw *Switch, addr *net.UDPAddr, pkt *pkt_t) error {
	var (
		c    = sw.net
		data []byte
		err  error
	)

	if pkt == nat_breaker_pkt {
		err = _net_conn_write(c.conn, addr, []byte("hello"))
		if err != nil {
			atomic.AddUint64(&c.num_err_pkt_snd, 1)
		} else {
			atomic.AddUint64(&c.num_pkt_snd, 1)
		}

	} else {
		c.log.Debugf("snd pkt: addr=%s hdr=%+v",
			addr, pkt.hdr)

		// marshal the packet
		data, err = pkt.format_pkt()
		if err != nil {
			atomic.AddUint64(&c.num_err_pkt_snd, 1)
			return err
		}

		// send the packet
		err = _net_conn_write(c.conn, addr, data)
		if err != nil {
			atomic.AddUint64(&c.num_err_pkt_snd, 1)
			return err
		} else {
			atomic.AddUint64(&c.num_pkt_snd, 1)
		}

	}

	return nil
}
