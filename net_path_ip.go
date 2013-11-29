package telehash

import (
	"net"
)

func ParseIPNetPath(str string) (NetPath, error) {
	addr, err := net.ResolveUDPAddr("udp", str)
	if err != nil {
		return nil, err
	}

	return NetPathFromAddr(addr), nil
}

func NetPathFromAddr(addri net.Addr) NetPath {
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
		zone = addr.Zone
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
		return &IPv4NetPath{cat, ip, port}
	} else {
		return &IPv6NetPath{cat, ip, zone, port}
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

func get_network_paths() ([]IPv4NetPath, error) {
	var (
		nets []IPv4NetPath
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
			var (
				ip   net.IP
				zone string
				cat  ip_addr_category
			)

			switch addr := addri.(type) {
			case *net.IPNet:
				ip = addr.IP
				zone = addr.Zone
			case *net.IPAddr:
				ip = addr.IP
				zone = addr.Zone
			}

			if iface.Flags & net.FlagLoopback {
				cat = ip_localhost
			} else if is_lan_ip(ip) {
				cat = ip_lan
			} else {
				cat = ip_wan
			}

			if is_ipv4(ip) {
				nets = append(nets, &IPv4NetPath{cat, ip, 0})
			} else {
				nets = append(nets, &IPv6NetPath{cat, ip, zone, 0})
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
	{net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.CIDRMask(10, 128)},
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
	{net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.CIDRMask(64, 128)},
}

func is_local_ip(ip net.IP) bool {
	for _, net := range local_ranges {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}
