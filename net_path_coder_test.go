package telehash_test

import (
	"github.com/telehash/gogotelehash/net"
	_ "github.com/telehash/gogotelehash/net/ipv4"
	_ "github.com/telehash/gogotelehash/net/ipv6"
	"testing"
)

func TestNetPathCoder(t *testing.T) {
	var table = []struct{ I, E string }{
		{`{"type":"ipv4","ip":"127.0.0.1","port":1024}`, ""},
		{`{"type":"ipv6","ip":"::1","port":1024}`, ""},
		{`{"type":"relay","c":"00112233445566778899aabbccddeeff"}`, ""},
		{`{"type":"ipv4","ip":"","port":1024}`, "invalid IPv4 address"},
		{`{"type":"ipv4","ip":"127.0.0.1","port":0}`, "invalid IPv4 address"},
		{`{"type":"ipv6","ip":"","port":1024}`, "invalid IPv6 address"},
		{`{"type":"ipv6","ip":"::1","port":0}`, "invalid IPv6 address"},
		{`{"type":"relay","c":""}`, "Invalid relay netpath"},
	}

	for i, row := range table {
		network, addr, err := net.DecodePath([]byte(row.I))
		if err != nil {
			if err.Error() != row.E {
				t.Errorf("[%d]: expected error to be %q but was %q", i, row.E, err)
			}
			continue
		}

		if network == "" {
			t.Errorf("[%d]: expected a netpath", i)
			continue
		}

		o, err := net.EncodePath(network, addr)
		if err != nil {
			if err.Error() != row.E {
				t.Errorf("[%d]: expected error to be %q but was %q", i, row.E, err)
			}
			continue
		}

		if string(o) != row.I {
			t.Errorf("[%d]: expected json to be %q but was %q", i, row.I, o)
		}
	}
}
