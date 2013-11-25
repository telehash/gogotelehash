package telehash

import (
	"net"
	"testing"
)

func TestUtilLanIPs(t *testing.T) {
	var ips = []string{
		"192.168.0.177",
		// "fe80::ee35:86ff:fe3d:6598",
	}

	for _, ipstr := range ips {
		ip := net.ParseIP(ipstr)
		if !is_lan_ip(ip) {
			t.Errorf("expected %s to be a Lan IP", ip)
		}
	}
}
