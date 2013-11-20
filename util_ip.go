package telehash

import (
	"net"
)

var lan_ranges = []net.IPNet{
	{net.IPv4(10, 0, 0, 0), net.CIDRMask(8, 32)},
	{net.IPv4(172, 16, 0, 0), net.CIDRMask(12, 32)},
	{net.IPv4(192, 168, 0, 0), net.CIDRMask(16, 32)},

	// only use IPv4 for now
	// net.IPNet{net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.CIDRMask(7, 128)},
	// net.IPNet{net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, net.CIDRMask(10, 128)},
}

func is_lan_ip(ip net.IP) bool {
	for _, net := range lan_ranges {
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

func get_lan_ip() (net.IP, bool) {
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPAddr); ok {
			if is_lan_ip(ip.IP) {
				return ip.IP, true
			}
		}
		if ip, ok := addr.(*net.IPNet); ok {
			if is_lan_ip(ip.IP) {
				return ip.IP, true
			}
		}
	}
	return net.IP{}, false
}
