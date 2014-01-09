package telehash

import (
	"net"
	"testing"
)

func Testnet_pathIPLan(t *testing.T) {
	var ips = []string{
		"192.168.0.177",
		"fc00::6598",
	}

	for _, ipstr := range ips {
		ip := net.ParseIP(ipstr)
		if !is_lan_ip(ip) {
			t.Errorf("expected %s to be a Lan IP", ip)
		}
	}
}
