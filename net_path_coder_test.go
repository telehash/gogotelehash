package telehash

import (
	"testing"
)

func TestNetPathCoder(t *testing.T) {
	var table = []struct{ I, E string }{
		{`{"type":"ipv4","ip":"127.0.0.1","port":1024}`, ""},
		{`{"type":"ipv6","ip":"::1","port":1024}`, ""},
		{`{"type":"relay","c":"00112233445566778899aabbccddeeff"}`, ""},
		{`{"type":"ipv4","ip":"","port":1024}`, "Invalid IPv4 netpath"},
		{`{"type":"ipv4","ip":"127.0.0.1","port":0}`, "Invalid IPv4 netpath"},
		{`{"type":"ipv6","ip":"","port":1024}`, "Invalid IPv6 netpath"},
		{`{"type":"ipv6","ip":"::1","port":0}`, "Invalid IPv6 netpath"},
		{`{"type":"relay","c":""}`, "Invalid relay netpath"},
	}

	for i, row := range table {
		np, err := DecodeNetPath([]byte(row.I))
		if err != nil {
			if err.Error() != row.E {
				t.Errorf("[%d]: expected error to be %q but was %q", i, row.E, err)
			}
			continue
		}

		if np == nil {
			t.Errorf("[%d]: expected a netpath", i)
			continue
		}

		o, err := EncodeNetPath(np)
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
