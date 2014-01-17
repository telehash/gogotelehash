package iputil

import (
	"net"
)

type Category uint8

const (
	CategoryUnknown Category = iota
	CategoryLocal
	CategoryLAN
	CategoryWAN
)

var category_strings = map[Category]string{
	CategoryUnknown: "unknown",
	CategoryLocal:   "local",
	CategoryLAN:     "lan",
	CategoryWAN:     "wan",
}

func (c Category) String() string {
	return category_strings[c]
}

func CategoryFor(ip net.IP) Category {
	if is_local_ip(ip) {
		return CategoryLocal
	}
	if is_lan_ip(ip) {
		return CategoryLAN
	}
	return CategoryWAN
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
