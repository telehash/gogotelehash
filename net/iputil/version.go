package iputil

import (
	"bytes"
	"net"
)

var ipv6_mapped_ipv4_address_prefix = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

func Version(ip net.IP) int {
	if len(ip) == net.IPv4len {
		return 4
	}
	if len(ip) == net.IPv6len && bytes.Equal(ipv6_mapped_ipv4_address_prefix, ip[:12]) {
		return 4
	}
	return 6
}
